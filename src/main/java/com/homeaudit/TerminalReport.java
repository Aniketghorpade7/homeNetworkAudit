package com.homeaudit;

/**
 * Renders a {@link ScanResult} as a colour-coded terminal summary.
 *
 * <p>ANSI colours are emitted only when writing to an interactive terminal (and the
 * {@code NO_COLOR} convention is honoured), so piped or redirected output stays clean
 * plain text.
 */
public class TerminalReport {

    private static final boolean COLOR =
            System.console() != null && System.getenv("NO_COLOR") == null;

    private static final String ESC = String.valueOf((char) 27); // ANSI escape
    private static final String RESET = ESC + "[0m";
    private static final String BOLD = ESC + "[1m";

    public static void print(ScanResult result) {
        System.out.println();
        System.out.println(style("=== Home Network Audit ===", BOLD));
        System.out.printf("Subnet: %s    Live hosts: %d    Generated: %s%n",
                result.subnet(), result.liveHostCount(), result.generatedAt());
        System.out.println();

        for (Device device : result.devices()) {
            printDevice(device);
        }

        Severity posture = result.networkPosture();
        System.out.println(style("Overall network posture: " + posture, colorFor(posture)));
    }

    private static void printDevice(Device device) {
        String risk = style(device.highestSeverity().toString(), colorFor(device.highestSeverity()));
        System.out.println(style(device.ip(), BOLD) + "   " + macLabel(device)
                + "   " + device.type() + "   (risk: " + risk + ")");

        if (device.openPorts().isEmpty()) {
            System.out.println("   (no common ports open)");
        } else {
            for (int port : device.openPorts()) {
                System.out.printf("   %-9s %s%n", port + "/tcp",
                        PortScanner.COMMON_PORTS.getOrDefault(port, "unknown"));
            }
        }

        for (Finding finding : device.findings()) {
            System.out.println("     " + style("[" + finding.severity() + "]", colorFor(finding.severity()))
                    + " " + finding.title());
            System.out.println("        fix: " + finding.remediation());
        }
        System.out.println();
    }

    private static String macLabel(Device device) {
        if (device.mac() == null) {
            return "[self / unresolved]";
        }
        String vendor = device.vendor() != null ? " · " + device.vendor() : "";
        return "[" + device.mac() + vendor + "]";
    }

    private static String colorFor(Severity severity) {
        return switch (severity) {
            case CRITICAL -> ESC + "[1;91m"; // bright bold red
            case HIGH     -> ESC + "[31m";   // red
            case MEDIUM   -> ESC + "[33m";   // yellow
            case LOW      -> ESC + "[36m";   // cyan
            case INFO     -> ESC + "[90m";   // grey
        };
    }

    private static String style(String text, String ansi) {
        return COLOR ? ansi + text + RESET : text;
    }
}
