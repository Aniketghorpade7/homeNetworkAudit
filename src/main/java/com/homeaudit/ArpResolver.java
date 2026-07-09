package com.homeaudit;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

/**
 * Resolves live host IP addresses to their hardware (MAC) addresses by reading the
 * operating system's ARP / neighbour cache.
 *
 * <p>This does NOT send any new packets: it reads what the OS already learned while we
 * were discovering and port-scanning hosts. It must therefore be called <em>after</em>
 * the scan, while the cache is still warm.
 *
 * <p>Only Linux ({@code ip neigh}) is fully supported for now. On other platforms it
 * degrades gracefully to an empty result rather than failing the whole audit.
 */
public class ArpResolver {

    /**
     * Reads the OS ARP cache and returns a map of {@code IP -> MAC}. Never throws;
     * on an unsupported OS or any error it returns an empty (possibly partial) map.
     */
    public static Map<String, String> resolveMacAddresses() {
        String os = System.getProperty("os.name", "").toLowerCase();

        if (os.contains("linux")) {
            return parseNeighbourTable();
        }

        System.out.println("[i] MAC/vendor resolution is only supported on Linux for now; skipping.");
        return new HashMap<>();
    }

    /**
     * Runs {@code ip neigh show} and parses each line into an IP -> MAC entry.
     * A typical line looks like:
     * <pre>10.245.180.1 dev wlan0 lladdr 34:60:f9:12:ab:cd REACHABLE</pre>
     * Entries without an {@code lladdr} token (e.g. FAILED / INCOMPLETE) are skipped.
     */
    private static Map<String, String> parseNeighbourTable() {
        Map<String, String> macByIp = new HashMap<>();

        try {
            ProcessBuilder pb = new ProcessBuilder("ip", "neigh", "show");
            pb.redirectErrorStream(true); // fold stderr into stdout so nothing blocks
            Process process = pb.start();

            try (BufferedReader reader =
                         new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    parseLine(line, macByIp);
                }
            }

            process.waitFor();
        } catch (IOException e) {
            System.err.println("[!] Could not read ARP cache: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // restore interrupted status
            System.err.println("[!] ARP resolution was interrupted.");
        }

        return macByIp;
    }

    /**
     * Extracts the IP (first token) and the MAC (token following {@code lladdr}) from a
     * single {@code ip neigh} line, adding it to {@code macByIp} if a MAC is present.
     * Parses defensively: lines of unexpected shape are simply ignored.
     */
    private static void parseLine(String line, Map<String, String> macByIp) {
        String[] tokens = line.trim().split("\\s+");
        if (tokens.length < 2) {
            return;
        }

        String ip = tokens[0];

        // Walk the tokens looking for "lladdr <mac>". IPv6 neighbours are parsed too but
        // are harmless: we only ever look these up by our IPv4 host strings.
        for (int i = 1; i < tokens.length - 1; i++) {
            if (tokens[i].equals("lladdr")) {
                macByIp.put(ip, tokens[i + 1].toLowerCase());
                return;
            }
        }
    }
}
