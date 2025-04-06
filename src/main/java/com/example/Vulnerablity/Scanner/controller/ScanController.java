package com.example.Vulnerablity.Scanner.controller;

import com.example.Vulnerablity.Scanner.DTO.ScanRequest;
import com.example.Vulnerablity.Scanner.DTO.ScanResponse;
import com.example.Vulnerablity.Scanner.service.ScanService;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/scan")
public class ScanController {

    @Autowired
    private ScanService scanService;

    @RateLimiter(name = "scanLimiter", fallbackMethod = "tooManyRequests")
    @PostMapping("/nmap")
    public ResponseEntity<ScanResponse> runNmapScan(@RequestBody ScanRequest request) {
        return ResponseEntity.ok(scanService.runNmapScan(request.getTarget()));
    }

    @RateLimiter(name = "scanLimiter", fallbackMethod = "tooManyRequests")
    @PostMapping("/zap")
    public ResponseEntity<ScanResponse> runZapScan(@RequestBody ScanRequest request) {
        return ResponseEntity.ok(scanService.runZapScan(request.getTarget()));
    }

    public ResponseEntity<ScanResponse> tooManyRequests(ScanRequest request, Exception ex) {
        return ResponseEntity.status(429)
                .body(new ScanResponse("Too many requests. Please try again later.", "RATE_LIMITED", null));
    }
}