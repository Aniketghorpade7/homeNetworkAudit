package com.homeaudit;

import java.net.SocketException;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.homeaudit.PortScanner.scanNetwork;

/**
 * Entry point. Runs the scan pipeline — subnet detection → host discovery → port scan →
 * MAC/vendor/type enrichment → rules analysis — into a single {@link Device} inventory,
 * then emits terminal, Markdown, and JSON reports.
 */
public class NetworkParser {

    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static void main(String[] args) {
        try {
            // 0. Load the data-driven security knowledge base (Task 10 / #5)
            List<Rule> rules = RuleLoader.load();
            System.out.println("[i] Loaded " + rules.size() + " security rules.");

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

            // 4. Enrichment: MAC (Task 6) + vendor (Task 7) + gateway/type (Task 8)
            Map<String, String> macByIp = ArpResolver.resolveMacAddresses();
            String gateway = DeviceClassifier.detectGateway();

            // 5. Assemble the device inventory (Task 9 / #4)
            List<Device> inventory = buildInventory(liveHosts, portResults, macByIp, gateway);

            // 6. Analyze against the security knowledge base (Task 11 / #6)
            new RulesEngine(rules).analyzeAll(inventory);

            // 7. Build the report model and emit every format (Phase 4)
            ScanResult result = new ScanResult(
                    scanTarget.getNetworkAddress() + "/" + scanTarget.prefixLength(),
                    LocalDateTime.now().format(TIMESTAMP),
                    inventory.size(),
                    RulesEngine.networkPosture(inventory),
                    inventory);

            TerminalReport.print(result);   // Task 12 / #7
            writeReports(result);           // Markdown (Task 13 / #8) + JSON (Task 14 / #9)

            System.out.printf("%nScan finished in %.2f seconds.%n", (endTime - startTime) / 1000.0);

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
            if (device.mac() != null) {
                device.setVendor(OuiVendorLookup.lookup(device.mac()));
            }
            device.setType(DeviceClassifier.classify(host, openPorts, gateway));
            inventory.add(device);
        }
        return inventory;
    }

    /** Writes the Markdown + JSON reports to ./reports/ and prints their paths. */
    private static void writeReports(ScanResult result) {
        Path dir = Path.of("reports");
        long timestamp = System.currentTimeMillis();
        Path markdown = dir.resolve("Network_Audit_" + timestamp + ".md");
        Path json = dir.resolve("Network_Audit_" + timestamp + ".json");

        MarkdownReport.write(result, markdown);
        JsonReport.write(result, json);

        System.out.println("\nReports written:");
        System.out.println("  " + markdown.toAbsolutePath());
        System.out.println("  " + json.toAbsolutePath());
    }
}
