package com.homeaudit;

/**
 * One entry in the security knowledge base: if a device exposes {@code port}
 * (a.k.a. {@code service}), it warrants a finding of the given {@code severity},
 * carrying a plain-English {@code explanation} and concrete {@code remediation}.
 *
 * <p>Loaded from the bundled {@code rules.json} by {@link RuleLoader}. Keeping the
 * knowledge in data (not Java code) is what lets remediation always reflect a real
 * finding rather than hardcoded boilerplate.
 */
public record Rule(int port,
                   String service,
                   Severity severity,
                   String title,
                   String explanation,
                   String remediation) {
}
