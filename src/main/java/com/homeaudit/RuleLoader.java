package com.homeaudit;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Loads the data-driven security rules bundled as the classpath resource
 * {@code /rules.json} into {@link Rule} objects, using Gson.
 *
 * <p>Fails loudly (throws) if the file is missing or malformed — a broken knowledge
 * base should stop the audit rather than silently produce an empty report.
 */
public class RuleLoader {

    private static final String RESOURCE = "/rules.json";

    /** Matches the top-level shape of rules.json: {@code { "rules": [ ... ] }}. */
    private record RuleFile(List<Rule> rules) {
    }

    /** Reads and parses {@code rules.json}, returning its rules. */
    public static List<Rule> load() {
        try (InputStream in = RuleLoader.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Rules file not found on classpath: " + RESOURCE);
            }
            try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
                RuleFile file = new Gson().fromJson(reader, RuleFile.class);
                if (file == null || file.rules() == null || file.rules().isEmpty()) {
                    throw new IllegalStateException("Rules file " + RESOURCE + " is empty or malformed.");
                }
                return file.rules();
            }
        } catch (JsonParseException e) {
            throw new IllegalStateException("Could not parse " + RESOURCE + ": " + e.getMessage(), e);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read " + RESOURCE, e);
        }
    }
}
