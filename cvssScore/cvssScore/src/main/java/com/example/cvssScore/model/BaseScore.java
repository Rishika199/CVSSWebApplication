package com.example.cvssScore.model;

import lombok.Data;
import org.springframework.stereotype.Component;
@Data
@Component
public class BaseScore {
    private String attackVector;
    private String attackComplexity;
    private String privilegesRequired;
    private String userInteraction;
    private String scope;
    private String confidentiality;
    private String integrity;
    private String Availability;

}
