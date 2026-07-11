package com.homeaudit;

import java.nio.file.Path;

/**
 * Parses command-line arguments into an immutable {@link Options}.
 *
 * <p>Hand-rolled (no library) so the parsing is fully transparent: a small state loop over
 * the argument array. Value flags (e.g. {@code --subnet X}) consume the next argument;
 * boolean flags just flip a field.
 */
public class Cli {

    public enum Format { TERMINAL, MARKDOWN, JSON, ALL }

    /** The parsed, validated command-line options. */
    public record Options(String subnet, Path outputDir, Format format, boolean iHavePermission) {
    }

    private static final String VERSION = "Home Network Audit 1.0.0";

    /**
     * Parses {@code args} into {@link Options}, or returns {@code null} to signal that the
     * program should stop now — either because {@code --help}/{@code --version} was printed,
     * or because an argument was invalid (an error was reported to stderr).
     */
    public static Options parse(String[] args) {
        String subnet = null;
        Path outputDir = Path.of("reports");
        Format format = Format.ALL;
        boolean iHavePermission = false;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "-h", "--help" -> {
                    printHelp();
                    return null;
                }
                case "-v", "--version" -> {
                    System.out.println(VERSION);
                    return null;
                }
                case "--i-have-permission" -> iHavePermission = true;
                case "--subnet" -> {
                    if (i + 1 >= args.length) {
                        return fail("--subnet needs a value, e.g. 192.168.1.0/24");
                    }
                    subnet = args[++i];
                }
                case "--output" -> {
                    if (i + 1 >= args.length) {
                        return fail("--output needs a directory path");
                    }
                    outputDir = Path.of(args[++i]);
                }
                case "--format" -> {
                    if (i + 1 >= args.length) {
                        return fail("--format needs one of: terminal, markdown, json, all");
                    }
                    Format parsed = parseFormat(args[++i]);
                    if (parsed == null) {
                        return fail("Unknown format: " + args[i]);
                    }
                    format = parsed;
                }
                default -> {
                    return fail("Unknown option: " + arg);
                }
            }
        }

        return new Options(subnet, outputDir, format, iHavePermission);
    }

    private static Format parseFormat(String value) {
        return switch (value.toLowerCase()) {
            case "terminal" -> Format.TERMINAL;
            case "markdown", "md" -> Format.MARKDOWN;
            case "json" -> Format.JSON;
            case "all" -> Format.ALL;
            default -> null;
        };
    }

    /** Reports an argument error to stderr and returns null so the caller stops. */
    private static Options fail(String message) {
        System.err.println("Error: " + message);
        System.err.println("Try '--help' for usage.");
        return null;
    }

    private static void printHelp() {
        System.out.println("""
                Home Network Audit — scan your local network and report device security risks.

                Usage:
                  home-network-audit [options]

                Options:
                  --subnet <cidr>        Scan this subnet (e.g. 192.168.1.0/24) instead of auto-detecting
                  --output <dir>         Directory for generated reports (default: reports)
                  --format <fmt>         terminal | markdown | json | all (default: all)
                  --i-have-permission    Confirm you are authorized to scan a non-local subnet
                  -h, --help             Show this help and exit
                  -v, --version          Show version and exit

                By default the tool scans only your own detected local network.""");
    }
}
