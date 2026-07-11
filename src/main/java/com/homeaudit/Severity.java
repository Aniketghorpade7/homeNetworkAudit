package com.homeaudit;

/**
 * Security severity levels, declared least-to-most severe.
 *
 * <p>The declaration order matters: natural {@link Enum} ordering (by {@code ordinal})
 * lets findings be rolled up to a worst-case level with {@code max(...)}.
 */
public enum Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
