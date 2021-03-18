package com.example.cvssScore.model;

import lombok.Data;
import org.springframework.stereotype.Component;
@Data
@Component
public class EnvironmentalScore {
    private String confidentialityRequirement;
    private String integrityRequirement;
    private String availabilityRequirement;
    private String modifiedAttackVector;
    private String modifiedAttackComplexity;
    private String modifiedPrivilegesRequired;
    private String modifiedUserInteraction;
    private String modifiedScope;
    private String modifiedConfidentiality;
    private String modifiedIntegrity;
    private String modifiedAvailability;

}
