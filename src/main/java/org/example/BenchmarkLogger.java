package org.example;

import java.io.FileWriter;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

public class BenchmarkLogger {
    private static BenchmarkLogger instance;
    private final Map<String, String> metrics = new LinkedHashMap<>();

    private BenchmarkLogger() {}

    public static BenchmarkLogger getInstance() {
        if (instance == null) {
            instance = new BenchmarkLogger();
        }
        return instance;
    }

    public void log(String metricName, String value) {
        metrics.put(metricName, value);
    }

    public void logSize(String metricName, byte[] data) {
        metrics.put(metricName, String.valueOf(data.length));
    }

    public long startTimer() {
        return System.nanoTime();
    }

    public long stopTimer(long startTime) {
        return (System.nanoTime() - startTime) / 1_000_000;
    }

    public void printResults() {
        System.out.println("Benchmark results:");
        for (Map.Entry<String, String> entry : metrics.entrySet()) {
            System.out.println(entry);
        }
    }

    public void writeToCSV(String filepath) throws IOException {
        try (FileWriter writer = new FileWriter(filepath, true)) {
            if (new java.io.File(filepath).length() == 0) {
                writer.write(String.join(",", metrics.keySet()) + "\n");
            }
            writer.write(String.join(",", metrics.values().stream().map(String::valueOf).toArray(String[]::new)) + "\n");
        }
    }
}
