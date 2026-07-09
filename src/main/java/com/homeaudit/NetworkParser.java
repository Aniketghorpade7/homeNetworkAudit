package com.homeaudit;

import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.homeaudit.PortScanner.COMMON_PORTS;
import static com.homeaudit.PortScanner.scanNetwork;

/**
 * Entry point. Runs the scan pipeline — subnet detection → host discovery → port scan →
 * MAC/type enrichment — into a single {@link Device} inventory, then renders it.
 *
 * <p>The inventory is the shared model that the rules engine (Phase 3) and the richer
 * report formats (Phase 4) plug into.
 */
public class NetworkParser {

    public static void main(String[] args) {
        try {
            // 1. Detect the local subnet to scan (Task 3)
            SubnetDetector.Subnet scanTarget = selectScanTarget();
            if (scanTarget == null) {
                System.out.println("Execution aborted: Could not map local private interfaces.");
                return;
            }

            // 2. Discover live hosts (Task 4)
            List<String> liveHosts = HostDiscovery.discoverLiveHosts(scanTarget);
            if (liveHosts.isEmpty()) {
                System.out.println("No responsive hosts found on the network.");
                return;
            }
            System.out.printf("%nFound %d live hosts. Beginning service mapping...%n%n", liveHosts.size());

            // 3. Port scan (Task 5)
            long startTime = System.currentTimeMillis();
            Map<String, List<Integer>> portResults = scanNetwork(liveHosts);
            long endTime = System.currentTimeMillis();

            // 4. Enrichment: MAC address (Task 6) + default gateway for typing (Task 8)
            Map<String, String> macByIp = ArpResolver.resolveMacAddresses();
            String gateway = DeviceClassifier.detectGateway();

            // 5. Assemble the single source of truth: the device inventory (Task 9 / #4)
            List<Device> inventory = buildInventory(liveHosts, portResults, macByIp, gateway);

            // 6. Render (minimal console view; richer reporters arrive in Phase 4)
            renderInventory(inventory);
            System.out.printf("%nPort scan finished in %.2f seconds.%n", (endTime - startTime) / 1000.0);

        } catch (Exception e) {
            System.err.println("Execution pipeline failure: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /** Picks the first private-range subnet as the scan target, or {@code null} if none. */
    private static SubnetDetector.Subnet selectScanTarget() throws SocketException {
        for (SubnetDetector.Subnet subnet : SubnetDetector.discoverSubnets()) {
            if (SubnetDetector.isPrivateAddress(subnet.ip())) {
                return subnet;
            }
        }
        return null;
    }

    /** Combines the raw scan outputs into a list of enriched {@link Device} objects. */
    private static List<Device> buildInventory(List<String> liveHosts,
                                               Map<String, List<Integer>> portResults,
                                               Map<String, String> macByIp,
                                               String gateway) {
        List<Device> inventory = new ArrayList<>();
        for (String host : liveHosts) {
            List<Integer> openPorts = portResults.getOrDefault(host, List.of());

            Device device = new Device(host);
            openPorts.stream().sorted().forEach(device::addPort);
            device.setMac(macByIp.get(host));
            device.setType(DeviceClassifier.classify(host, openPorts, gateway));
            inventory.add(device);
        }
        return inventory;
    }

    /** Minimal console rendering of the inventory (superseded by Phase 4 reporters). */
    private static void renderInventory(List<Device> inventory) {
        for (Device device : inventory) {
            String mac = device.mac() != null ? device.mac() : "no ARP entry (self/unresolved)";
            System.out.printf("%s   [%s]   %s%n", device.ip(), mac, device.type());

            if (device.openPorts().isEmpty()) {
                System.out.println("  (no common ports open)");
            } else {
                device.openPorts().forEach(port ->
                        System.out.printf("  %-8s %s%n", port + "/tcp", COMMON_PORTS.getOrDefault(port, "unknown")));
            }
        }
    }
}
