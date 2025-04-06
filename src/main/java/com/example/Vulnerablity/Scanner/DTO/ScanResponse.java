package com.example.Vulnerablity.Scanner.DTO;

import lombok.Data;

import java.util.List;

@Data
public class ScanResponse {
    private String scanResults;
    private String status;
    private List<String> vulnerabilities;

    public ScanResponse(String scanResults, String status, List<String> vulnerabilities) {
        this.scanResults = scanResults;
        this.status = status;
        this.vulnerabilities = vulnerabilities;
    }
}