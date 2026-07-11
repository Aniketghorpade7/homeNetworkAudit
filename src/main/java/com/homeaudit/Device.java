package com.homeaudit;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * One host discovered on the network, enriched as the scan progresses: its open ports,
 * hardware (MAC) address, vendor, inferred type, and any security findings.
 *
 * <p>Mutable by design — the pipeline builds a Device up in stages (ports, then MAC, then
 * type, then findings from the rules engine). It is the single source of truth consumed by
 * every report format.
 */
public class Device {

    private final String ip;
    private String mac;                  // null if unresolved (e.g. this machine)
    private String vendor;               // null until OUI lookup is wired in (issue #2)
    private String type = "Unknown device";
    private final List<Integer> openPorts = new ArrayList<>();
    private final List<Finding> findings = new ArrayList<>();

    public Device(String ip) {
        this.ip = ip;
    }

    public String ip() {
        return ip;
    }

    public String mac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public String vendor() {
        return vendor;
    }

    public void setVendor(String vendor) {
        this.vendor = vendor;
    }

    public String type() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<Integer> openPorts() {
        return openPorts;
    }

    public void addPort(int port) {
        openPorts.add(port);
    }

    public List<Finding> findings() {
        return findings;
    }

    public void addFinding(Finding finding) {
        findings.add(finding);
    }

    /** The worst severity among this device's findings, or {@link Severity#INFO} if none. */
    public Severity highestSeverity() {
        return findings.stream()
                .map(Finding::severity)
                .max(Comparator.naturalOrder())
                .orElse(Severity.INFO);
    }
}
