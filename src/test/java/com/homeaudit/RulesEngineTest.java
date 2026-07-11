package com.homeaudit;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the RulesEngine — the pure, deterministic core of the analyzer.
 *
 * <p>Most tests build a small hand-made list of rules (via {@link #sampleRules()}) instead
 * of loading the real {@code rules.json}. That keeps each test self-contained: it can't
 * break later just because the knowledge base was edited. The first test deliberately uses
 * the real loader to show that style too.
 */
public class RulesEngineTest {

    /**
     * A tiny, fixed rule set for the hand-built tests: SSH (22) is LOW, Telnet (23) is
     * CRITICAL. Building rules in the test keeps assertions precise and independent of
     * whatever rules.json happens to contain.
     */
    private static List<Rule> sampleRules() {
        return List.of(
                new Rule(22, "ssh", Severity.LOW, "SSH open",
                        "SSH is reachable.", "Use key-based authentication."),
                new Rule(23, "telnet", Severity.CRITICAL, "Telnet open",
                        "Telnet is plaintext.", "Disable Telnet; use SSH.")
        );
    }

    @Test
    void telnetIsFlaggedCritical() {
        // Arrange
        Device d1 = new Device("192.168.1.50");
        d1.addPort(23);
        RulesEngine e1 = new RulesEngine(RuleLoader.load());

        //Act
        e1.analyze(d1);

        // Assert
        // FIX: removed the leading "void" — assertEquals is a method *call* here, not a
        // method declaration. "void assertEquals(...)" made the compiler think you were
        // declaring a new method inside the test, which is a syntax error.
        assertEquals(1, d1.findings().size());
        assertEquals(Severity.CRITICAL, d1.findings().get(0).severity());
    }

    @Test
    void severityRollsUpToTheWorstPort() {
        // A device with both a LOW port (22) and a CRITICAL port (23) must roll up to CRITICAL.
        Device device = new Device("192.168.1.51");
        device.addPort(22);   // LOW
        device.addPort(23);   // CRITICAL
        RulesEngine engine = new RulesEngine(sampleRules());

        engine.analyze(device);

        assertEquals(2, device.findings().size());                 // both ports produced findings
        assertEquals(Severity.CRITICAL, device.highestSeverity()); // the worst one wins
    }

    @Test
    void portWithNoMatchingRuleProducesNoFinding() {
        // Port 9999 has no rule in our sample set, so analysis must add nothing.
        Device device = new Device("192.168.1.52");
        device.addPort(9999);
        RulesEngine engine = new RulesEngine(sampleRules());

        engine.analyze(device);

        assertEquals(0, device.findings().size());
        assertTrue(device.findings().isEmpty());
    }

    @Test
    void deviceWithNoOpenPortsHasInfoPosture() {
        // No ports => no findings => the "worst severity" falls back to INFO.
        Device device = new Device("192.168.1.53");
        RulesEngine engine = new RulesEngine(sampleRules());

        engine.analyze(device);

        assertEquals(0, device.findings().size());
        assertEquals(Severity.INFO, device.highestSeverity());
    }

    @Test
    void networkPostureIsTheWorstAcrossAllDevices() {
        // One quiet device (LOW) and one risky device (CRITICAL): the network posture is CRITICAL.
        Device quiet = new Device("192.168.1.10");
        quiet.addPort(22); // LOW
        Device risky = new Device("192.168.1.11");
        risky.addPort(23); // CRITICAL

        RulesEngine engine = new RulesEngine(sampleRules());
        List<Device> inventory = List.of(quiet, risky);
        engine.analyzeAll(inventory);

        assertEquals(Severity.CRITICAL, RulesEngine.networkPosture(inventory));
    }

    @Test
    void remediationComesFromTheMatchedRule() {
        // Proves findings are data-driven: the finding's remediation is exactly the rule's,
        // never hardcoded text.
        Device device = new Device("192.168.1.54");
        device.addPort(23);
        RulesEngine engine = new RulesEngine(sampleRules());

        engine.analyze(device);

        assertEquals("Disable Telnet; use SSH.", device.findings().get(0).remediation());
    }
}
