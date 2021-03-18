package com.example.cvssScore.model;

import lombok.Data;
import org.springframework.stereotype.Component;

@Data
@Component
public class TemporalScore {
    private String exploitCodeMaturity;
    private String remediationLevel;
    private String reportConfidence;
}
