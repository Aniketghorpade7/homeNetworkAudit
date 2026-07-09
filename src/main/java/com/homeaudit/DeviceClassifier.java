package com.homeaudit;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

/**
 * Best-effort classification of a device's <em>type</em> from cheap signals: whether it is
 * the network's default gateway, and which well-known ports it exposes.
 *
 * <p>Heuristic and deliberately modest for v1 — richer port coverage and a MAC-vendor hint
 * can sharpen this later. Anything unrecognised falls back to "Unknown device".
 */
public class DeviceClassifier {

    /**
     * Detects the IPv4 default gateway by reading {@code ip route show default}
     * (Linux). Returns {@code null} if it cannot be determined.
     */
    public static String detectGateway() {
        try {
            ProcessBuilder pb = new ProcessBuilder("ip", "route", "show", "default");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            try (BufferedReader reader =
                         new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    // e.g. "default via 10.245.180.1 dev wlan0 proto dhcp ..."
                    String[] tokens = line.trim().split("\\s+");
                    for (int i = 0; i < tokens.length - 1; i++) {
                        if (tokens[i].equals("via")) {
                            process.waitFor();
                            return tokens[i + 1];
                        }
                    }
                }
            }
            process.waitFor();
        } catch (IOException e) {
            // gateway unknown – not fatal
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return null;
    }

    /**
     * Infers a human-readable device type from the host's identity and open ports.
     * The gateway check wins first; otherwise the most specific port signature applies.
     */
    public static String classify(String ip, List<Integer> openPorts, String gatewayIp) {
        if (ip.equals(gatewayIp)) {
            return "Router / Gateway";
        }
        if (openPorts == null || openPorts.isEmpty()) {
            return "Unknown device";
        }

        if (hasAny(openPorts, 445, 139, 3389)) {
            return "Windows host";
        }
        if (openPorts.contains(3306)) {
            return "Database server";
        }
        if (openPorts.contains(53)) {
            return "DNS server";
        }
        if (hasAny(openPorts, 80, 443, 8080)) {
            return "Web service / admin panel";
        }
        if (openPorts.contains(22)) {
            return "SSH host (Linux/Unix)";
        }
        return "Unknown device";
    }

    private static boolean hasAny(List<Integer> ports, int... candidates) {
        for (int c : candidates) {
            if (ports.contains(c)) {
                return true;
            }
        }
        return false;
    }
}
