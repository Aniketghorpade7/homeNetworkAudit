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

}
