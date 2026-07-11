package com.homeaudit;

import java.net.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SubnetDetector
{
    public record Subnet(String iface, Inet4Address ip, int prefixLength) {
        /**
         * Calculate the base network address
         * by applying the subnet mask using bitwise operations.
         */
        public String getNetworkAddress() {
            byte[] ipBytes = ip.getAddress();

            // Handle byte-to-int sign extension using '& 0xFF'
            int ipInt = ((ipBytes[0] & 0xFF) << 24) |
                    ((ipBytes[1] & 0xFF) << 16) |
                    ((ipBytes[2] & 0xFF) << 8) |
                    (ipBytes[3] & 0xFF);

            // Generate the subnet Mask (e.g. /24 turns into 24 ones followed by 8 zeros)
            int mask = -1 << (32 - prefixLength);

            // Apply the mask to zero out the host bits
            int networkInt = ipInt & mask;

            // Return of clean output
            return String.format("%d.%d.%d.%d",
                    (networkInt >> 24) & 0xFF,
                    (networkInt >> 16) & 0xFF,
                    (networkInt >> 8) & 0xFF,
                    networkInt & 0xFF);
        }

        @Override
        public String toString() {
            return String.format("%-8s %s/%-2d  → network %s/%d",
                    iface, ip.getHostAddress(), prefixLength, getNetworkAddress(), prefixLength);
        }
    }

    /**
     *  Enumerates all active, non-loopback network interfaces and returns IPv4 subnet
     */
    public static List<Subnet> discoverSubnets()    throws SocketException{
        List<Subnet> subnets = new ArrayList<>();

        // Convert old school Enumeration into modern List for clean looping
        var interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());

        for(NetworkInterface ni : interfaces) {
            // Filter: must be active (up) and Not a loopback (127.0.0.0) address
            if(!ni.isUp() || ni.isLoopback()){
                continue;
            }

            for(InterfaceAddress ia : ni.getInterfaceAddresses()){
                //Keep only IPv4; skip IPv6
                if (ia.getAddress() instanceof  Inet4Address ipv4){
                    subnets.add(new Subnet(ni.getName(), ipv4, ia.getNetworkPrefixLength()));
                }
            }
        }
        return subnets;
    }

    /**
     *  Helper to identify if an IP belongs to a standard private LAN range
     */
    public static boolean isPrivateAddress(Inet4Address ip){
        byte[] bytes = ip.getAddress();
        int first = bytes[0] & 0xFF;
        int second = bytes[1] & 0xFF;

        if(first == 10) return true;
        if(first == 172 && (second >= 16 && second <= 31))  return true;
        if(first == 192 && second == 168)   return true;

        return false;
    }

    /**
     * Builds a {@link Subnet} from a CIDR string such as {@code "192.168.1.0/24"} — used by
     * the {@code --subnet} flag. Throws {@link IllegalArgumentException} if malformed.
     */
    public static Subnet fromCidr(String cidr) {
        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Subnet must be in CIDR form, e.g. 192.168.1.0/24");
        }

        int prefix;
        try {
            prefix = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid prefix length in: " + cidr);
        }
        if (prefix < 0 || prefix > 32) {
            throw new IllegalArgumentException("Prefix length must be 0-32, got: " + prefix);
        }

        try {
            InetAddress address = InetAddress.getByName(parts[0].trim());
            if (!(address instanceof Inet4Address ipv4)) {
                throw new IllegalArgumentException("Only IPv4 subnets are supported: " + cidr);
            }
            return new Subnet("manual", ipv4, prefix);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IPv4 address in: " + cidr);
        }
    }

    /**
     * True if the given subnet is one the machine is actually connected to — i.e. one of
     * our own interface IPs falls within it. Used to gate scanning of foreign networks
     * behind an explicit permission flag.
     */
    public static boolean isLocalSubnet(Subnet requested) throws SocketException {
        int requestedMask = maskFor(requested.prefixLength());
        int requestedNetwork = toInt(requested.ip()) & requestedMask;

        for (Subnet mine : discoverSubnets()) {
            if ((toInt(mine.ip()) & requestedMask) == requestedNetwork) {
                return true;
            }
        }
        return false;
    }

    /** Packs an IPv4 address into a 32-bit int (with the usual &amp; 0xFF sign-extension guard). */
    private static int toInt(Inet4Address address) {
        byte[] b = address.getAddress();
        return ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
    }

    /** Builds a /prefix netmask as a 32-bit int (prefix 0 → 0.0.0.0). */
    private static int maskFor(int prefix) {
        return prefix == 0 ? 0 : -1 << (32 - prefix);
    }

}
