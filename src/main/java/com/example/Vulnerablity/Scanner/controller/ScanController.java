package com.example.Vulnerablity.Scanner.controller;

import com.example.Vulnerablity.Scanner.DTO.ScanRequest;
import com.example.Vulnerablity.Scanner.DTO.ScanResponse;
import com.example.Vulnerablity.Scanner.model.ScanHistory;
import com.example.Vulnerablity.Scanner.model.ScanResult;
import com.example.Vulnerablity.Scanner.service.ScanService;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/scan")
public class ScanController {

    private final ScanService scanService;

    @Autowired
    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    /**
     * Main endpoint to perform a vulnerability scan with specified options
     * @param request Contains target and scan preferences
     * @return Scan results
     */
    @PostMapping
    @RateLimiter(name = "scanRateLimiter")
    public ResponseEntity<ScanResponse> scan(@RequestBody ScanRequest request) {
        // Validate the target URL
        if (request.getTarget() == null || request.getTarget().isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ScanResponse("Target URL cannot be empty", "FAILED", null));
        }

        // Perform the scan operation
        ScanResponse response = scanService.performScan(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint to run a specific type of scan (nmap, zap, all)
     * @param scanType The type of scan to run
     * @param request Contains the target information
     * @return Scan results
     */
    @PostMapping("/{scanType}")
    @RateLimiter(name = "scanRateLimiter")
    public ResponseEntity<ScanResponse> scanWithType(
            @PathVariable String scanType,
            @RequestBody ScanRequest request) {

        if (request.getTarget() == null || request.getTarget().isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ScanResponse("Target URL cannot be empty", "FAILED", null));
        }

        // Check if scan type is valid
        if (!scanType.equalsIgnoreCase("nmap") &&
                !scanType.equalsIgnoreCase("zap") &&
                !scanType.equalsIgnoreCase("all")) {
            return ResponseEntity.badRequest().body(
                    new ScanResponse("Invalid scan type. Must be 'nmap', 'zap', or 'all'", "FAILED", null));
        }

        // Set the scan type from the path variable
        request.setScanType(scanType);

        // Perform the scan operation
        ScanResponse response = scanService.performScan(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Quick endpoint for running Nmap scan
     * @param target The target to scan
     * @return Nmap scan results
     */
    @GetMapping("/nmap")
    @RateLimiter(name = "scanRateLimiter")
    public ResponseEntity<ScanResponse> quickNmapScan(@RequestParam String target) {
        if (target == null || target.isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ScanResponse("Target URL cannot be empty", "FAILED", null));
        }

        ScanResponse response = scanService.runNmapScan(target);
        return ResponseEntity.ok(response);
    }

    /**
     * Quick endpoint for running ZAP scan
     * @param target The target to scan
     * @return ZAP scan results
     */
    @GetMapping("/zap")
    @RateLimiter(name = "scanRateLimiter")
    public ResponseEntity<ScanResponse> quickZapScan(@RequestParam String target) {
        if (target == null || target.isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ScanResponse("Target URL cannot be empty", "FAILED", null));
        }

        ScanResponse response = scanService.runZapScan(target);
        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint to retrieve scan history for a specific target or all targets
     * @param target Optional target to filter history by
     * @return List of previous scans
     */
    @GetMapping("/history")
    public ResponseEntity<List<ScanHistory>> getScanHistory(
            @RequestParam(required = false) String target) {
        try {
            List<ScanHistory> history = scanService.getScanHistory(target);
            return ResponseEntity.ok(history);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Endpoint to get detailed results of a specific scan by ID
     * @param scanId The ID of the scan to retrieve
     * @return Detailed scan results
     */
    @GetMapping("/result/{scanId}")
    public ResponseEntity<?> getScanResult(@PathVariable String scanId) {
        try {
            ScanResult result = scanService.getScanResultById(scanId);

            if (result == null) {
                return ResponseEntity.notFound().build();
            }

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Endpoint to validate a target without performing a full scan
     * @param target The target URL or IP to validate
     * @return Validation result
     */
    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateTarget(@RequestParam String target) {
        if (target == null || target.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("valid", false, "reason", "Target cannot be empty"));
        }

        boolean isValid = scanService.isValidTarget(target);
        if (isValid) {
            return ResponseEntity.ok(Map.of("valid", true));
        } else {
            return ResponseEntity.ok(Map.of(
                    "valid", false,
                    "reason", "Target must be a valid domain or IP address"
            ));
        }
    }

    /**
     * Endpoint to cancel an ongoing scan
     * @param scanId The ID of the scan to cancel
     * @return Cancellation result
     */
    @DeleteMapping("/{scanId}")
    public ResponseEntity<?> cancelScan(@PathVariable String scanId) {
        try {
            boolean cancelled = scanService.cancelScan(scanId);

            if (cancelled) {
                return ResponseEntity.ok(Map.of(
                        "cancelled", true,
                        "message", "Scan successfully cancelled"
                ));
            } else {
                return ResponseEntity.ok(Map.of(
                        "cancelled", false,
                        "message", "No active scan found with the provided ID"
                ));
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }
}