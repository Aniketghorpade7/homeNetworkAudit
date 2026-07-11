package com.homeaudit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for OuiVendorLookup — resolving a MAC's first three octets to a vendor via the
 * bundled IEEE OUI table. Pure lookup logic; the table is a bundled resource, so no
 * network is involved.
 */
public class OuiVendorLookupTest {

    @Test
    void knownOuiResolvesToVendor() {
        // 28:6F:B9 is registered to Nokia Shanghai Bell in the IEEE registry. We assert a
        // substring rather than the exact company name so the test is robust to minor
        // formatting changes in the registry data.
        String vendor = OuiVendorLookup.lookup("28:6F:B9:11:22:33");
        assertTrue(vendor.contains("Nokia"), "expected a Nokia vendor, got: " + vendor);
    }

    @Test
    void randomizedMacIsReportedAsRandomized() {
        // The 0x02 bit of the first octet marks a locally-administered (randomized) MAC.
        // 0x02 has that bit set, so this must be detected before any table lookup.
        assertEquals("Unknown (randomized MAC)", OuiVendorLookup.lookup("02:00:00:00:00:00"));
    }

    @Test
    void unmappedGlobalOuiReturnsUnknownVendor() {
        // FC:FF:FF is globally administered (0x02 bit clear) but currently unassigned,
        // so it falls through to the generic "Unknown vendor".
        assertEquals("Unknown vendor", OuiVendorLookup.lookup("FC:FF:FF:00:00:00"));
    }

    @Test
    void nullOrTooShortInputReturnsUnknownVendor() {
        assertEquals("Unknown vendor", OuiVendorLookup.lookup(null));
        assertEquals("Unknown vendor", OuiVendorLookup.lookup("12"));
    }
}
