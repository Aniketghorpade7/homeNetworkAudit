package com.homeaudit;

import java.io.*;
import java.net.SocketException;
import java.util.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import static com.homeaudit.PortScanner.COMMON_PORTS;
import static com.homeaudit.PortScanner.scanNetwork;
import static com.homeaudit.SubnetDetector.*;

public class NetworkParser {

    public static void main(String[] args) {
        try {
            // 1. Uncover Subnet Map (Task 3)
            List<SubnetDetector.Subnet> subnets = SubnetDetector.discoverSubnets();
            SubnetDetector.Subnet scanTarget = null;
            for (SubnetDetector.Subnet s : subnets) {
                if (SubnetDetector.isPrivateAddress(s.ip())) {
                    scanTarget = s;
                    break;
                }
            }

            if (scanTarget == null) {
                System.out.println("Execution aborted: Could not map local private interfaces.");
                return;
            }

            // 2. Discover Active Hosts via ICMP/Echo Sweep (Task 4)
            List<String> liveHosts = HostDiscovery.discoverLiveHosts(scanTarget);
            if (liveHosts.isEmpty()) {
                System.out.println("No responsive hosts found on the network.");
                return;
            }

            System.out.printf("%nFound %d live hosts. Beginning service mapping...%n%n", liveHosts.size());

            // 3. Scan Network Ports via Pure Java Virtual Threads (Task 5)
            long startTime = System.currentTimeMillis();
            Map<String, List<Integer>> results = scanNetwork(liveHosts);
            long endTime = System.currentTimeMillis();

            // 4. Resolve MAC addresses from the (warm) OS ARP cache (Task 6 / #1)
            Map<String, String> macByIp = ArpResolver.resolveMacAddresses();

            // 5. Detect the default gateway so we can label the router (Task 8 / #3)
            String gateway = DeviceClassifier.detectGateway();

            // 6. Output Render Engine
            for (String host : liveHosts) {
                List<Integer> openPorts = results.get(host);
                String mac = macByIp.getOrDefault(host, "no ARP entry (self/unresolved)");
                String type = DeviceClassifier.classify(host, openPorts, gateway);

                System.out.printf("%s   [%s]   %s%n", host, mac, type);

                if (openPorts.isEmpty()) {
                    System.out.println("  (no common ports open)");
                } else {
                    // Sort numerically for output clarity
                    openPorts.stream().sorted().forEach(port -> {
                        String serviceName = COMMON_PORTS.getOrDefault(port, "unknown");
                        System.out.printf("  %-8s %s%n", port + "/tcp", serviceName);
                    });
                }
            }

            System.out.printf("%nPort scan finished in %.2f seconds.%n", (endTime - startTime) / 1000.0);

        } catch (Exception e) {
            System.err.println("Execution pipeline failure: " + e.getMessage());
            e.printStackTrace();
        }
    }
}



class Device
{
    String ip;
    String label = "UNKNOWN DEVICE";
    String risk = "LOW";
    String os = "UNKNOWN OS";
    List<String> openPorts = new ArrayList<>(); 

    Device(String ip){
        this.ip = ip;
    }

    void addPort(String portInfo){
        openPorts.add(portInfo);

        if (portInfo.contains("microsoft-ds") || portInfo.contains("netbios")) {
            this.os = "Windows";
            this.label = "Workstation";
        } else if (portInfo.contains("Ubuntu") || portInfo.contains("Dropbear")) {
            this.os = "Linux";
        }

        if (portInfo.contains("21/tcp") || portInfo.contains("23/tcp")) {
            this.risk = "CRITICAL";
            this.label = "Legacy/Vulnerable Service";
        } else if (portInfo.contains("80/tcp") || portInfo.contains("443/tcp")) {
            this.label = "Web Server/Admin Panel";
        }
    }

    @Override
    public String toString(){
        return String.format("[%s] IP: %s | Label: %s | Ports: %s", risk, ip, label, openPorts);
    }
}

class ReportGenerator
{
    public static void saveMarkdown(HashMap<String, Device> inventory)
    {
        String fileName = "../reports/Network_Audit_" + System.currentTimeMillis() + ".md";
        
        try (PrintWriter writer = new PrintWriter(new FileWriter(fileName))) {
            writer.println("# Network Security Audit Report");
            writer.println("Generated on: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            writer.println("\n## Executive Summary");
            writer.println("This report details the devices found on the local network and their associated risks.");
            
            writer.println("\n| IP Address | Operating System | Label | Risk Level | Open Services |");
            writer.println("| :--- | :--- | :--- | :--- | :--- |");

            for (Device d : inventory.values()) {
                String ports = String.join(", ", d.openPorts);
                writer.printf("| %s | %s | %s | **%s** | %s |\n", 
                              d.ip, d.os, d.label, d.risk, ports);
            }

            writer.println("\n## Recommended Remediation");
            writer.println("1. **Close Port 3306:** Database services should not be reachable via the LAN.");
            writer.println("2. **Disable SMBv1:** Ensure Windows hosts are using SMBv2/3 to prevent legacy exploits.");
            
            System.out.println("[+] Report saved successfully: " + fileName);
        } catch (IOException e) {
            System.err.println("[-] Error writing report: " + e.getMessage());
        }
    }
}
