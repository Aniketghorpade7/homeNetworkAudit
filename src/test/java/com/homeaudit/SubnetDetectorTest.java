package com.homeaudit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the pure, deterministic parts of SubnetDetector: CIDR parsing and the
 * network-address masking.
 *
 * <p>Interface enumeration ({@code discoverSubnets}) and {@code isLocalSubnet} depend on the
 * host's live network state, so they are verified by running the app rather than unit-tested.
 */
public class SubnetDetectorTest {

    @Test
    void fromCidrParsesAddressPrefixAndNetwork() {
        SubnetDetector.Subnet subnet = SubnetDetector.fromCidr("192.168.1.42/24");

        assertEquals("192.168.1.42", subnet.ip().getHostAddress());
        assertEquals(24, subnet.prefixLength());
        assertEquals("192.168.1.0", subnet.getNetworkAddress()); // /24 zeroes the last octet
    }

    @Test
    void networkAddressMasksToThePrefix() {
        // /16 keeps the first two octets and zeroes the rest.
        SubnetDetector.Subnet subnet = SubnetDetector.fromCidr("10.5.6.7/16");
        assertEquals("10.5.0.0", subnet.getNetworkAddress());
    }

    @Test
    void fromCidrRejectsMalformedInput() {
        // assertThrows runs the lambda and passes only if the expected exception is thrown.
        assertThrows(IllegalArgumentException.class, () -> SubnetDetector.fromCidr("not-a-subnet"));
        assertThrows(IllegalArgumentException.class, () -> SubnetDetector.fromCidr("192.168.1.0"));    // no /prefix
        assertThrows(IllegalArgumentException.class, () -> SubnetDetector.fromCidr("192.168.1.0/99")); // prefix > 32
    }
}
