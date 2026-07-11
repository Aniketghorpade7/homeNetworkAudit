package com.homeaudit;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Maps a hardware MAC address to its manufacturer using the IEEE OUI registry.
 *
 * <p>The first three octets of a MAC (the "OUI") are assigned to a vendor by the IEEE.
 * A trimmed copy of the public registry is bundled as the classpath resource
 * {@code /oui.tsv}, one {@code OUI<TAB>vendor} entry per line.
 *
 * <p>The table is loaded lazily on first lookup and cached for the process lifetime.
 */
public class OuiVendorLookup {

    private static final String RESOURCE = "/oui.tsv";
    private static final String UNKNOWN = "Unknown vendor";
    private static final String RANDOMIZED = "Unknown (randomized MAC)";

    private static Map<String, String> vendorByOui; // lazily initialised, see table()

    /**
     * Returns the manufacturer for {@code mac}, or a friendly "unknown" string.
     * Locally-administered / randomized MACs are reported as such: they are
     * intentionally not registered to any vendor, so a lookup would be meaningless.
     */
    public static String lookup(String mac) {
        if (mac == null || mac.isBlank()) {
            return UNKNOWN;
        }

        // Strip separators (":", "-") and normalise to uppercase hex.
        String hex = mac.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        if (hex.length() < 6) {
            return UNKNOWN;
        }

        // Bit 0x02 of the first octet marks a locally-administered (randomized) address.
        int firstOctet = Integer.parseInt(hex.substring(0, 2), 16);
        if ((firstOctet & 0x02) != 0) {
            return RANDOMIZED;
        }

        return table().getOrDefault(hex.substring(0, 6), UNKNOWN);
    }

    /** Returns the OUI table, loading it on first use. */
    private static synchronized Map<String, String> table() {
        if (vendorByOui == null) {
            vendorByOui = load();
        }
        return vendorByOui;
    }

    private static Map<String, String> load() {
        Map<String, String> map = new HashMap<>(50_000);

        try (InputStream in = OuiVendorLookup.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                System.err.println("[!] OUI database not found on classpath ("
                        + RESOURCE + "); vendor lookup disabled.");
                return map;
            }

            try (BufferedReader reader =
                         new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    int tab = line.indexOf('\t');
                    if (tab <= 0) {
                        continue;
                    }
                    map.put(line.substring(0, tab), line.substring(tab + 1));
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load OUI database", e);
        }

        return map;
    }
}
