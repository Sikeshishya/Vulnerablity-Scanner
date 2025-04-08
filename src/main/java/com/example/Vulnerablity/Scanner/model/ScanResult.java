// ScanResult.java
package com.example.Vulnerablity.Scanner.model;

import java.time.LocalDateTime;
import java.util.List;

public class ScanResult {
    private String id;
    private String target;
    private String scanType;
    private String status;
    private String output;
    private List<String> vulnerabilities;
    private LocalDateTime scanTime;

    // Constructors
    public ScanResult() {
    }

    public ScanResult(String id, String target, String scanType, String status, String output,
                      List<String> vulnerabilities, LocalDateTime scanTime) {
        this.id = id;
        this.target = target;
        this.scanType = scanType;
        this.status = status;
        this.output = output;
        this.vulnerabilities = vulnerabilities;
        this.scanTime = scanTime;
    }

    // Getters and Setters
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public String getScanType() {
        return scanType;
    }

    public void setScanType(String scanType) {
        this.scanType = scanType;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
    }

    public List<String> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<String> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public LocalDateTime getScanTime() {
        return scanTime;
    }

    public void setScanTime(LocalDateTime scanTime) {
        this.scanTime = scanTime;
    }
}