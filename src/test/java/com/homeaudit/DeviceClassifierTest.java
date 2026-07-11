package com.homeaudit;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for DeviceClassifier.classify — the pure heuristic that labels a device from its
 * gateway status and open-port signature.
 *
 * <p>{@code detectGateway} shells out to {@code ip route}, so it is environment-dependent
 * and verified by running the app rather than unit-tested here.
 */
public class DeviceClassifierTest {

    @Test
    void gatewayIpIsClassifiedAsRouter() {
        // When the device IP equals the detected gateway, that check wins first.
        assertEquals("Router / Gateway",
                DeviceClassifier.classify("192.168.1.1", List.of(53), "192.168.1.1"));
    }

    @Test
    void smbPortIsClassifiedAsWindowsHost() {
        assertEquals("Windows host",
                DeviceClassifier.classify("192.168.1.10", List.of(445), null));
    }

    @Test
    void dnsPortIsClassifiedAsDnsServer() {
        // Not the gateway, and no Windows/database ports — port 53 makes it a DNS server.
        assertEquals("DNS server",
                DeviceClassifier.classify("192.168.1.5", List.of(53), "192.168.1.1"));
    }

    @Test
    void deviceWithNoPortsIsUnknown() {
        assertEquals("Unknown device",
                DeviceClassifier.classify("192.168.1.99", List.of(), null));
    }
}

