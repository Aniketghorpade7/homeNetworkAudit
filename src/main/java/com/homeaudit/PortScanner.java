package com.homeaudit;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class PortScanner
{
    private static final int TIMEOUT_MS = 400;

    public static final Map<Integer, String> COMMON_PORTS = Map.ofEntries(
            Map.entry(21, "ftp"),    Map.entry(22, "ssh"),    Map.entry(23, "telnet"),
            Map.entry(25, "smtp"),   Map.entry(53, "domain"), Map.entry(80, "http"),
            Map.entry(110, "pop3"),  Map.entry(111, "rpcbind"), Map.entry(135, "msrpc"),
            Map.entry(139, "netbios-ssn"), Map.entry(143, "imap"), Map.entry(443, "https"),
            Map.entry(445, "microsoft-ds"), Map.entry(993, "imaps"), Map.entry(995, "pop3s"),
            Map.entry(1723, "pptp"), Map.entry(3306, "mysql"), Map.entry(3389, "ms-wbt-server"),
            Map.entry(5900, "vnc"),  Map.entry(8080, "http-proxy")
    );

    // An immutable structure to hold individual async probe results
    private record PortProbeResult(String host, int port, boolean isOpen) {}

    /**
     * Scans a single host sequentially for debugging or isolated usage
     */
    public static Map<String, List<Integer>> scanNetwork(List<String> liveHosts){
        Map<String, List<Integer>> networkReport = new HashMap<>();
        List<Future<PortProbeResult>> futures = new ArrayList<>();

        // Initialize report categories for all active hosts
        for (String host : liveHosts) {
            networkReport.put(host, new ArrayList<>());
        }

        System.out.printf("Initiating parallel connect-scan across %d hosts...%n", liveHosts.size());

        // Concurrency Block: Spawn thousands of ultra-lightweight virtual threads
        try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
            for (String host : liveHosts) {
                for (int port : COMMON_PORTS.keySet()) {
                    final String targetHost = host;
                    final int targetPort = port;

                    futures.add(pool.submit(() -> {
                        boolean open = isPortOpen(targetHost, targetPort);
                        return new PortProbeResult(targetHost, targetPort, open);
                    }));
                }
            }

            // Gather structural output metrics
            for (Future<PortProbeResult> f : futures) {
                try {
                    PortProbeResult result = f.get();
                    if (result.isOpen()) {
                        networkReport.get(result.host()).add(result.port());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    System.err.println("Port scanning was interrupted prematurely.");
                    break;
                } catch (ExecutionException e) {
                    // Fail-silent for an individual socket error inside a task
                }
            }
        }

        return networkReport;
    }

    /**
     * The core pure Java network probe loop.
     * No JNI native locks; safely unmounts virtual threads while waiting.
     */
    private static boolean isPortOpen(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            return true; // No exception encountered = Port is wide open!
        } catch (ConnectException e) {
            // CLOSED: The target host immediately rejected the packet (RST flag sent back)
            return false;
        } catch (SocketTimeoutException e) {
            // FILTERED: No response within timeline (Firewall cleanly dropped packet)
            return false;
        } catch (IOException e) {
            // General connection or interface drop error
            return false;
        }
    }
}
