package com.homeaudit;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class HostDiscovery
{
    private static final int TIMEOUT_MS = 1000; // Balanced timeout fir home WIFI/Ethernate

    /**
     * Probes a subnet concurrently using java Virtual Threads to locate live hosts.
     */
    public static List<String> discoverLiveHosts(SubnetDetector.Subnet target) {
        List<String> liveHosts = new ArrayList<>();
        List<Future<String>> futures = new ArrayList<>();

        byte[] ipBytes = target.ip().getAddress();
        int ipInt = ((ipBytes[0] & 0xFF) << 24) |
                ((ipBytes[1] & 0xFF) << 16) |
                ((ipBytes[2] & 0xFF) << 8)  |
                (ipBytes[3] & 0xFF);

        int mask = -1 << (32 - target.prefixLength());
        int networkInt = ipInt & mask;
        int broadcastInt = networkInt | ~mask;

        System.out.printf("Scanning hosts on subnet %s/%d...%n", target.getNetworkAddress(), target.prefixLength());

        // Try-with-resources handles auto-shutdown of Virtual thread
        try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {

            // Loop from the first usable host (Network + 1) to the last usable host (Broadcast - 1)
            for (int i = networkInt + 1; i < broadcastInt; i++) {
                final String targetIp = intToIp(i);

                // Submit independent blocking I/O calls to the virtual thread pool
                futures.add(pool.submit(() -> {
                    try {
                        InetAddress addr = InetAddress.getByName(targetIp);
                        // isReachable() blocks here. Virtual threads safely park for free.
                        if (addr.isReachable(TIMEOUT_MS)) {
                            return targetIp;
                        }
                    } catch (IOException e) {
                        // Silent catch: Host is unmapped, unreachable, or dropped packet
                    }
                    return null;
                }));
            }

            // 3. Gotcha Handling: Collect results and handle checked exceptions from Future.get()
            for (Future<String> f : futures) {
                try {
                    String result = f.get(); // Blocks until this explicit task completes
                    if (result != null) {
                        liveHosts.add(result);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt(); // Restore interrupted status
                    System.err.println("Scanning execution was interrupted.");
                    break;
                } catch (ExecutionException e) {
                    System.err.println("Task execution failed: " + e.getCause());
                }
            }
        } // The virtual thread pool closes gracefully here, blocking until all straggler tasks exit.

        return liveHosts;
    }

    /**
     * Helper to reconstruct a dotted-decimal IP string from a 32-bit integer.
     */
    private static String intToIp(int ip) {
        return String.format("%d.%d.%d.%d",
                (ip >> 24) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF,
                ip & 0xFF);
    }
}
