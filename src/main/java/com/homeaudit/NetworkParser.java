package com.homeaudit;

import java.io.*;
import java.util.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class NetworkParser {
    public static void main(String[] args) throws Exception 
    {
        System.out.println("Home Network Audit v0.1 — starting up");
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
