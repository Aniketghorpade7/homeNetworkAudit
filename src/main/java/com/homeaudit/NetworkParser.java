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
        Cli.Options options = Cli.parse(args);
        if (options == null) {
            return; // --help / --version / bad args already handled
        }

        try {
            // 0. Load the data-driven security knowledge base (Task 10 / #5)
            List<Rule> rules = RuleLoader.load();
            System.out.println("[i] Loaded " + rules.size() + " security rules.");

            // 1. Choose the subnet: --subnet override or auto-detect (Task 15 / #10)
            SubnetDetector.Subnet scanTarget = (options.subnet() != null)
                    ? SubnetDetector.fromCidr(options.subnet())
                    : selectScanTarget();
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

            emitReports(result, options);   // terminal (#7) / markdown (#8) / json (#9), per --format

            System.out.printf("%nScan finished in %.2f seconds.%n", (endTime - startTime) / 1000.0);

        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
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

    /** Emits the reports selected by {@code --format} to the configured output directory. */
    private static void emitReports(ScanResult result, Cli.Options options) {
        Cli.Format format = options.format();

        if (format == Cli.Format.ALL || format == Cli.Format.TERMINAL) {
            TerminalReport.print(result);
        }

        long timestamp = System.currentTimeMillis();
        if (format == Cli.Format.ALL || format == Cli.Format.MARKDOWN) {
            Path markdown = options.outputDir().resolve("Network_Audit_" + timestamp + ".md");
            MarkdownReport.write(result, markdown);
            System.out.println("Markdown report: " + markdown.toAbsolutePath());
        }
        if (format == Cli.Format.ALL || format == Cli.Format.JSON) {
            Path json = options.outputDir().resolve("Network_Audit_" + timestamp + ".json");
            JsonReport.write(result, json);
            System.out.println("JSON report: " + json.toAbsolutePath());
        }
    }
}
