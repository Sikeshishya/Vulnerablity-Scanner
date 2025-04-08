// ScanHistory.java
package com.example.Vulnerablity.Scanner.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import java.time.LocalDateTime;

@Entity
public class ScanHistory {

    @Id
    private String id;

    private String target;
    private String scanType;
    private String status;
    private LocalDateTime scanTime;
    private int vulnerabilitiesFound;

    // Constructors
    public ScanHistory() {
    }

    public ScanHistory(String id, String target, String scanType, String status,
                       LocalDateTime scanTime, int vulnerabilitiesFound) {
        this.id = id;
        this.target = target;
        this.scanType = scanType;
        this.status = status;
        this.scanTime = scanTime;
        this.vulnerabilitiesFound = vulnerabilitiesFound;
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

    public LocalDateTime getScanTime() {
        return scanTime;
    }

    public void setScanTime(LocalDateTime scanTime) {
        this.scanTime = scanTime;
    }

    public int getVulnerabilitiesFound() {
        return vulnerabilitiesFound;
    }

    public void setVulnerabilitiesFound(int vulnerabilitiesFound) {
        this.vulnerabilitiesFound = vulnerabilitiesFound;
    }
}