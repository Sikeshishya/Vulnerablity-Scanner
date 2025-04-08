package com.example.Vulnerablity.Scanner.DTO;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ScanRequest {
    private String target;
    private String scanType;

    // Explicit getters (in case Lombok isn't working)
    public String getTarget() {
        return target;
    }

    public String getScanType() {
        return scanType;
    }
}