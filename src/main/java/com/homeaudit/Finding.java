package com.homeaudit;

/**
 * A single security observation about a {@link Device}: what it is, why it matters, and
 * what to do about it.
 *
 * <p>Findings are produced by the rules engine from a data-driven knowledge base, so the
 * {@code remediation} always corresponds to an actual finding — never hardcoded boilerplate.
 */
public record Finding(Severity severity, String title, String explanation, String remediation) {
}
