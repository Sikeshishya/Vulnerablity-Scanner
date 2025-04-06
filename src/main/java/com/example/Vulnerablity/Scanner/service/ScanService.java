package com.example.Vulnerablity.Scanner.service;

import com.example.Vulnerablity.Scanner.DTO.ScanResponse;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

@Service
public class ScanService {

    public ScanResponse runNmapScan(String target) {
        try {
            // Validate target first
            if (!isValidTarget(target)) {
                return new ScanResponse("Invalid target format", "FAILED", null);
            }

            // Windows-specific command
            String command = "C:\\Program Files (x86)\\Nmap\\nmap.exe -sV -T4 " + target;

            // Alternative if the above path doesn't work:
            // String command = "nmap -sV -T4 " + target;

            Process process = Runtime.getRuntime().exec(command);

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
            if (exitCode != 0) {
                return new ScanResponse("Scan failed with exit code: " + exitCode, "FAILED", null);
            }

            // Parse results
            String scanResults = output.toString();
            List<String> vulnerabilities = analyzeResults(scanResults);

            return new ScanResponse(
                    scanResults,
                    vulnerabilities.isEmpty() ? "CLEAN" : "VULNERABLE",
                    vulnerabilities
            );

        } catch (IOException | InterruptedException e) {
            return new ScanResponse("Scan failed: " + e.getMessage(), "FAILED", null);
        }
    }

    public ScanResponse runZapScan(String target) {
        try {
            if (!isValidTarget(target)) {
                return new ScanResponse("Invalid target format", "FAILED", null);
            }

            // For ZAP scanning, you would typically call ZAP's API
            // This is a simplified example
            String command = "curl -X GET http://zap-server/JSON/ascan/action/scan/?url=" + target;
            Process process = Runtime.getRuntime().exec(command);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            int exitCode = process.waitFor();
            if (exitCode != 0) {
                return new ScanResponse("ZAP scan failed", "FAILED", null);
            }

            return new ScanResponse(
                    output.toString(),
                    "COMPLETED",
                    parseZapResults(output.toString())
            );

        } catch (IOException | InterruptedException e) {
            return new ScanResponse("ZAP scan error: " + e.getMessage(), "FAILED", null);
        }
    }

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

    private boolean isValidTarget(String target) {
        // Basic validation - allow domains and IPs
        return target.matches("^([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$") ||
                target.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    }

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

        return vulnerabilities;
    }
}