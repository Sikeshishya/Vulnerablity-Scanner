package com.example.Vulnerablity.Scanner.service;

import com.example.Vulnerablity.Scanner.DTO.ScanRequest;
import com.example.Vulnerablity.Scanner.DTO.ScanResponse;
import com.example.Vulnerablity.Scanner.model.ScanHistory;
import com.example.Vulnerablity.Scanner.model.ScanResult;
import com.example.Vulnerablity.Scanner.repository.ScanHistoryRepository;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class ScanService {

    // In-memory storage for ongoing scans - would be replaced with database in production
    private final Map<String, Process> ongoingScans = new ConcurrentHashMap<>();

    // In-memory storage for scan results - would be replaced with database in production
    private final Map<String, ScanResult> scanResults = new ConcurrentHashMap<>();

    // Repository dependency for scan history
    // We're assuming this will be implemented in your project
    @Autowired(required = false)
    private ScanHistoryRepository scanHistoryRepository;

    /**
     * Main method to perform vulnerability scanning based on the request
     * @param request The scan request containing target and scan options
     * @return ScanResponse with results
     */
    @RateLimiter(name = "scanRateLimiter")
    public ScanResponse performScan(ScanRequest request) {
        // Extract the target from the request
        String target = request.getTarget();

        // Generate unique ID for this scan
        String scanId = UUID.randomUUID().toString();

        // Check what type of scan was requested, default to Nmap if not specified
        String scanType = request.getScanType() != null ? request.getScanType().toLowerCase() : "nmap";

        // Perform the appropriate scan based on type
        ScanResponse response;
        switch (scanType) {
            case "zap":
                response = runZapScan(target);
                break;
            case "all":
                // Combine results from multiple scanners
                ScanResponse nmapResponse = runNmapScan(target);
                ScanResponse zapResponse = runZapScan(target);
                response = combineResults(nmapResponse, zapResponse);
                break;
            case "nmap":
            default:
                response = runNmapScan(target);
                break;
        }

        // Save scan result
        saveResult(scanId, target, scanType, response);

        return response;
    }

    /**
     * Run an Nmap vulnerability scan
     * @param target The target URL or IP to scan
     * @return ScanResponse with scan results
     */
    public ScanResponse runNmapScan(String target) {
        try {
            // Validate target first
            if (!isValidTarget(target)) {
                return new ScanResponse("Invalid target format", "FAILED", null);
            }

            // Generate a unique scan ID
            String scanId = UUID.randomUUID().toString();

            // Windows-specific command
            String command = "C:\\Program Files (x86)\\Nmap\\nmap.exe -sV -T4 " + target;

            // Alternative if the above path doesn't work:
            // String command = "nmap -sV -T4 " + target;

            Process process = Runtime.getRuntime().exec(command);

            // Store the process for possible cancellation
            ongoingScans.put(scanId, process);

            // Read output
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            // Wait for process to complete
            int exitCode = process.waitFor();

            // Remove from ongoing scans
            ongoingScans.remove(scanId);

            if (exitCode != 0) {
                return new ScanResponse("Scan failed with exit code: " + exitCode, "FAILED", null);
            }

            // Parse results
            String scanResults = output.toString();
            List<String> vulnerabilities = analyzeResults(scanResults);

            ScanResponse response = new ScanResponse(
                    scanResults,
                    vulnerabilities.isEmpty() ? "CLEAN" : "VULNERABLE",
                    vulnerabilities
            );

            // Save the scan result
            saveResult(scanId, target, "nmap", response);

            return response;

        } catch (IOException | InterruptedException e) {
            return new ScanResponse("Scan failed: " + e.getMessage(), "FAILED", null);
        }
    }

    /**
     * Run a ZAP vulnerability scan
     * @param target The target URL to scan
     * @return ScanResponse with scan results
     */
    public ScanResponse runZapScan(String target) {
        try {
            if (!isValidTarget(target)) {
                return new ScanResponse("Invalid target format", "FAILED", null);
            }

            // Generate a unique scan ID
            String scanId = UUID.randomUUID().toString();

            // For ZAP scanning, you would typically call ZAP's API
            // This is a simplified example
            String command = "curl -X GET http://zap-server/JSON/ascan/action/scan/?url=" + target;
            Process process = Runtime.getRuntime().exec(command);

            // Store the process for possible cancellation
            ongoingScans.put(scanId, process);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            int exitCode = process.waitFor();

            // Remove from ongoing scans
            ongoingScans.remove(scanId);

            if (exitCode != 0) {
                return new ScanResponse("ZAP scan failed", "FAILED", null);
            }

            ScanResponse response = new ScanResponse(
                    output.toString(),
                    "COMPLETED",
                    parseZapResults(output.toString())
            );

            // Save the scan result
            saveResult(scanId, target, "zap", response);

            return response;

        } catch (IOException | InterruptedException e) {
            return new ScanResponse("ZAP scan error: " + e.getMessage(), "FAILED", null);
        }
    }

    /**
     * Combine results from multiple scanners
     * @param responses The scan responses to combine
     * @return A combined ScanResponse
     */
    private ScanResponse combineResults(ScanResponse... responses) {
        StringBuilder combinedOutput = new StringBuilder();
        List<String> combinedVulnerabilities = new ArrayList<>();
        String overallStatus = "CLEAN";

        for (ScanResponse response : responses) {
            // Append each scanner's output
            combinedOutput.append("--- ").append(response.getStatus()).append(" SCAN RESULTS ---\n");
            combinedOutput.append(response.getOutput()).append("\n\n");

            // Combine vulnerabilities
            if (response.getVulnerabilities() != null) {
                combinedVulnerabilities.addAll(response.getVulnerabilities());
            }

            // Update overall status
            if (response.getStatus().equals("VULNERABLE") || response.getStatus().equals("FAILED")) {
                overallStatus = response.getStatus();
            }
        }

        // If any vulnerabilities were found, mark as vulnerable
        if (!combinedVulnerabilities.isEmpty()) {
            overallStatus = "VULNERABLE";
        }

        return new ScanResponse(
                combinedOutput.toString(),
                overallStatus,
                combinedVulnerabilities
        );
    }

    /**
     * Parse ZAP scan results for vulnerabilities
     * @param zapOutput The raw ZAP output
     * @return List of identified vulnerabilities
     */
    private List<String> parseZapResults(String zapOutput) {
        List<String> vulnerabilities = new ArrayList<>();
        // Add your ZAP results parsing logic here
        if (zapOutput.contains("XSS")) {
            vulnerabilities.add("Cross-Site Scripting (XSS) vulnerability detected");
        }
        if (zapOutput.contains("SQL Injection")) {
            vulnerabilities.add("SQL Injection vulnerability detected");
        }
        return vulnerabilities;
    }

    /**
     * Validate if the target is in the proper format
     * @param target The target URL or IP to validate
     * @return true if valid, false otherwise
     */
    public boolean isValidTarget(String target) {
        // Basic validation - allow domains and IPs
        return target.matches("^([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$") ||
                target.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    }

    /**
     * Analyze Nmap output for vulnerabilities
     * @param nmapOutput The raw Nmap output
     * @return List of identified vulnerabilities
     */
    private List<String> analyzeResults(String nmapOutput) {
        List<String> vulnerabilities = new ArrayList<>();

        // Example vulnerability detection
        if (nmapOutput.contains("80/tcp open") && nmapOutput.contains("Apache")) {
            if (nmapOutput.contains("Apache/2.4.49")) {
                vulnerabilities.add("CVE-2021-41773 (Apache Path Traversal)");
            }
        }

        if (nmapOutput.contains("22/tcp open") && nmapOutput.contains("OpenSSH")) {
            vulnerabilities.add("SSH service exposed - ensure proper hardening");
        }

        // Additional vulnerability checks
        if (nmapOutput.contains("3306/tcp open") && nmapOutput.contains("MySQL")) {
            vulnerabilities.add("MySQL database exposed - restrict access if not intended");
        }

        if (nmapOutput.contains("21/tcp open") && nmapOutput.contains("FTP")) {
            vulnerabilities.add("FTP service exposed - consider using SFTP instead");
        }

        if (nmapOutput.contains("telnet")) {
            vulnerabilities.add("Telnet service detected - use SSH instead for secure communications");
        }

        return vulnerabilities;
    }

    /**
     * Save the scan result to our storage
     * @param scanId Unique identifier for the scan
     * @param target Target that was scanned
     * @param scanType Type of scan performed
     * @param response Scan response containing results
     */
    private void saveResult(String scanId, String target, String scanType, ScanResponse response) {
        // Create and save the scan result
        ScanResult result = new ScanResult(
                scanId,
                target,
                scanType,
                response.getStatus(),
                response.getOutput(),
                response.getVulnerabilities(),
                LocalDateTime.now()
        );

        // Store in our in-memory map
        scanResults.put(scanId, result);

        // Create and save scan history entry
        ScanHistory history = new ScanHistory(
                scanId,
                target,
                scanType,
                response.getStatus(),
                LocalDateTime.now(),
                response.getVulnerabilities() != null ? response.getVulnerabilities().size() : 0
        );

        // If repository is available, save to database
        if (scanHistoryRepository != null) {
            scanHistoryRepository.save(history);
        }
    }

    /**
     * Get scan history for a specific target or all targets
     * @param target Optional target to filter history by
     * @return List of scan history entries
     */
    public List<ScanHistory> getScanHistory(String target) {
        // If we're using a repository, use it
        if (scanHistoryRepository != null) {
            if (target != null && !target.isEmpty()) {
                return scanHistoryRepository.findByTarget(target);
            } else {
                return scanHistoryRepository.findAll();
            }
        }

        // Otherwise, create history entries from our in-memory results
        List<ScanHistory> history = new ArrayList<>();
        for (ScanResult result : scanResults.values()) {
            if (target == null || target.isEmpty() || result.getTarget().equals(target)) {
                ScanHistory entry = new ScanHistory(
                        result.getId(),
                        result.getTarget(),
                        result.getScanType(),
                        result.getStatus(),
                        result.getScanTime(),
                        result.getVulnerabilities() != null ? result.getVulnerabilities().size() : 0
                );
                history.add(entry);
            }
        }

        return history;
    }

    /**
     * Get detailed scan result by ID
     * @param scanId ID of the scan to retrieve
     * @return The scan result or null if not found
     */
    public ScanResult getScanResultById(String scanId) {
        return scanResults.get(scanId);
    }

    /**
     * Cancel an ongoing scan
     * @param scanId ID of the scan to cancel
     * @return true if successfully cancelled, false otherwise
     */
    public boolean cancelScan(String scanId) {
        Process process = ongoingScans.get(scanId);
        if (process != null) {
            process.destroy();
            ongoingScans.remove(scanId);

            // Update scan result status to cancelled
            ScanResult result = scanResults.get(scanId);
            if (result != null) {
                result.setStatus("CANCELLED");
            }

            return true;
        }
        return false;
    }
}