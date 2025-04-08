package com.example.Vulnerablity.Scanner.DTO;

import lombok.Data;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ScanResponse {
    private String scanId;
    private String target;
    private String scanType;
    private LocalDateTime scanStartTime;
    private LocalDateTime scanEndTime;
    private String status;
    private String scanResults;
    private List<String> vulnerabilities;
    private Map<String, String> scanMetrics;
    private int vulnerabilityCount;
    private String severityLevel;
    private String summary;
    private boolean scanSuccessful;

    // Add explicit getters
    public String getStatus() {
        return status;
    }

    public String getOutput() {
        return scanResults;
    }

    public List<String> getVulnerabilities() {
        return vulnerabilities;
    }

    // Keep the simple constructor
    public ScanResponse(String scanResults, String status, List<String> vulnerabilities) {
        this.scanResults = scanResults;
        this.status = status;
        this.vulnerabilities = vulnerabilities;
        this.scanSuccessful = !"FAILED".equals(status);
        this.vulnerabilityCount = vulnerabilities != null ? vulnerabilities.size() : 0;
        this.scanStartTime = LocalDateTime.now();
        this.scanEndTime = LocalDateTime.now();
    }
}