package com.homeaudit;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Writes a {@link ScanResult} as a human-readable Markdown report (renders on GitHub).
 * All remediation text is sourced from actual {@link Finding}s — nothing is hardcoded.
 */
public class MarkdownReport {

    public static void write(ScanResult result, Path file) {
        String markdown = render(result);
        try {
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            Files.writeString(file, markdown, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write Markdown report to " + file, e);
        }
    }

    static String render(ScanResult result) {
        StringBuilder md = new StringBuilder();

        md.append("# Home Network Audit Report\n\n");
        md.append("- **Generated:** ").append(result.generatedAt()).append("\n");
        md.append("- **Subnet scanned:** ").append(result.subnet()).append("\n");
        md.append("- **Live hosts:** ").append(result.liveHostCount()).append("\n");
        md.append("- **Overall network posture:** ").append(result.networkPosture()).append("\n\n");

        md.append("## Device Inventory\n\n");
        md.append("| IP | MAC | Vendor | Type | Risk | Open ports |\n");
        md.append("| --- | --- | --- | --- | --- | --- |\n");
        for (Device d : result.devices()) {
            md.append("| ").append(d.ip())
                    .append(" | ").append(orDash(d.mac()))
                    .append(" | ").append(orDash(d.vendor()))
                    .append(" | ").append(d.type())
                    .append(" | **").append(d.highestSeverity()).append("**")
                    .append(" | ").append(portList(d))
                    .append(" |\n");
        }
        md.append("\n");

        md.append("## Findings & Remediation\n\n");
        boolean anyFindings = false;
        for (Device d : result.devices()) {
            if (d.findings().isEmpty()) {
                continue;
            }
            anyFindings = true;
            md.append("### ").append(d.ip()).append(" — ").append(d.type()).append("\n\n");
            for (Finding f : d.findings()) {
                md.append("- **[").append(f.severity()).append("] ").append(f.title()).append("**  \n");
                md.append("  ").append(f.explanation()).append("  \n");
                md.append("  _Remediation:_ ").append(f.remediation()).append("\n");
            }
            md.append("\n");
        }
        if (!anyFindings) {
            md.append("No findings — none of the security rules matched the services discovered.\n");
        }

        return md.toString();
    }

    private static String orDash(String value) {
        return (value == null || value.isBlank()) ? "—" : value;
    }

    private static String portList(Device d) {
        if (d.openPorts().isEmpty()) {
            return "—";
        }
        StringBuilder sb = new StringBuilder();
        for (int port : d.openPorts()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(port).append("/tcp ").append(PortScanner.COMMON_PORTS.getOrDefault(port, "?"));
        }
        return sb.toString();
    }
}
