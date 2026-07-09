package com.homeaudit;

import java.util.List;

/**
 * The complete result of one audit run: scan metadata plus the enriched, analyzed device
 * inventory. It is the single input every report format (terminal, Markdown, JSON) reads,
 * and the root object serialized to JSON.
 */
public record ScanResult(String subnet,
                         String generatedAt,
                         int liveHostCount,
                         Severity networkPosture,
                         List<Device> devices) {
}
