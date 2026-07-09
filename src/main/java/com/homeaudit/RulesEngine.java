package com.homeaudit;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Applies the data-driven security knowledge base to scanned devices.
 *
 * <p>For each device, every {@link Rule} whose port is open produces a {@link Finding}
 * attached to that device. Because findings (and their remediation) come only from rules
 * that actually fired, the report can never contain advice unrelated to what was found.
 *
 * <p>This class is pure and deterministic — {@code (rules, device) -> findings} — which
 * makes it the primary unit-test seam.
 */
public class RulesEngine {

    private final Map<Integer, Rule> rulesByPort;

    public RulesEngine(List<Rule> rules) {
        // Index rules by port for O(1) lookup; on the (unexpected) duplicate, keep the first.
        this.rulesByPort = rules.stream()
                .collect(Collectors.toMap(Rule::port, rule -> rule, (first, second) -> first));
    }

    /** Attaches findings to a single device based on its open ports. */
    public void analyze(Device device) {
        for (int port : device.openPorts()) {
            Rule rule = rulesByPort.get(port);
            if (rule != null) {
                device.addFinding(new Finding(
                        rule.severity(), rule.title(), rule.explanation(), rule.remediation()));
            }
        }
    }

    /** Analyzes every device in the inventory in place. */
    public void analyzeAll(List<Device> inventory) {
        inventory.forEach(this::analyze);
    }

    /**
     * The worst severity across the whole inventory — the overall network posture.
     * Returns {@link Severity#INFO} for an empty or finding-free inventory.
     */
    public static Severity networkPosture(List<Device> inventory) {
        return inventory.stream()
                .map(Device::highestSeverity)
                .max(Comparator.naturalOrder())
                .orElse(Severity.INFO);
    }
}
