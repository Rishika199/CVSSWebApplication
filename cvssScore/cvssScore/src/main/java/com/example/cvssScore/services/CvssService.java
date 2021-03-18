package com.example.cvssScore.services;

import com.example.cvssScore.dao.Cvssrepo;
import com.example.cvssScore.model.BaseScore;
import com.example.cvssScore.model.CvssScore;
import com.example.cvssScore.model.EnvironmentalScore;
import com.example.cvssScore.model.TemporalScore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CvssService {
    @Autowired
    Cvssrepo cvssrepo;
    public String createVectorString(BaseScore baseScore, EnvironmentalScore environmentalScore, TemporalScore temporalScore){
        String unformattedVectorString= "CVSS:3.0//AV:%s//AC:%s//PR:%s//UI:%s//S:%s//C:%s//I:%s//A:%s//E:%s//RL:%s//RC:%s//CR:%s//IR:%s//AR:%s//MAV:%s//MAC:%s//MPR:%s//MUI:%s//MS:%s//MC:%s//MI:%s//MA:%s";
        return String.format(unformattedVectorString,baseScore.getAttackVector(),baseScore.getAttackComplexity(),baseScore.getPrivilegesRequired(),
                baseScore.getUserInteraction(),baseScore.getScope(),baseScore.getConfidentiality(), baseScore.getIntegrity(),baseScore.getAvailability(),
                temporalScore.getExploitCodeMaturity(),temporalScore.getRemediationLevel(),temporalScore.getReportConfidence(),
                environmentalScore.getConfidentialityRequirement(),environmentalScore.getIntegrityRequirement(),environmentalScore.getAvailabilityRequirement(),
                environmentalScore.getModifiedAttackVector(),environmentalScore.getModifiedAttackComplexity(),environmentalScore.getModifiedPrivilegesRequired(),
                environmentalScore.getModifiedUserInteraction(),environmentalScore.getModifiedScope(),environmentalScore.getModifiedConfidentiality(),
                environmentalScore.getModifiedIntegrity(),environmentalScore.getModifiedAvailability()
                );
    }

    public float calculateBaseScore(BaseScore baseScore){
        float bs= 0;
        float exploitability;
        float impact=0;
        float iss;
        float confidentiality= CvssScore.baseScoreMap.get(baseScore.getConfidentiality());
        float integrity=CvssScore.baseScoreMap.get(baseScore.getIntegrity());
        float availability= CvssScore.baseScoreMap.get(baseScore.getAvailability());
        float av= CvssScore.baseScoreMap.get(baseScore.getAttackVector());
        float ac= CvssScore.baseScoreMap.get(baseScore.getAttackComplexity());
        float pr= CvssScore.baseScoreMap.get(baseScore.getPrivilegesRequired());
        float ui= CvssScore.baseScoreMap.get(baseScore.getUserInteraction());
        iss= 1-((1-confidentiality)*(1-integrity)*(1-availability));

        if (baseScore.getScope().equals("U")){
            impact= (float)(6.42*iss);
        }
        else if (baseScore.getScope().equals("C")){
            impact= (float) ((7.52*(iss-0.029))-(3.25*(Math.pow((iss-0.02),15))));
            if (pr==0.62){
                pr=(float)0.68;
            }
            else if(pr==0.27){
                pr= (float)0.5;
            }
        }
        exploitability= (float)(8.22*av*ac*pr*ui);

        if( impact<=0){
            bs=0;
        }
        else {
            if (baseScore.getScope().equals("U")){
                bs= Math.min((impact+exploitability), 10);
            }
            else if( baseScore.getScope().equals("C"))
            bs= (float)Math.min((1.08*(impact+exploitability)),10);
        }
        return bs;


    }
    public float calculateTemporalScore(TemporalScore temporalScore, BaseScore baseScore){
        float ts;
        float calBaseScore= calculateBaseScore(baseScore);
        float ecm= CvssScore.temporalScoreMap.get(temporalScore.getExploitCodeMaturity());
        float rl= CvssScore.temporalScoreMap.get(temporalScore.getRemediationLevel());
        float rc= CvssScore.temporalScoreMap.get(temporalScore.getReportConfidence());
        ts= calBaseScore*ecm*rl*rc;
        return ts;

    }

    public float calculateEnvironmentalScore(EnvironmentalScore environmentalScore, TemporalScore temporalScore){
        float modifiedImpact=0;
        float es=0;
            float mav= CvssScore.environmentalScoreMap.get(environmentalScore.getModifiedAttackVector());
            float mac= CvssScore.environmentalScoreMap.get(environmentalScore.getModifiedAttackComplexity());
            float mpr= CvssScore.environmentalScoreMap.get(environmentalScore.getModifiedPrivilegesRequired());
            float mui= CvssScore.environmentalScoreMap.get(environmentalScore.getModifiedUserInteraction());
            float cr= CvssScore.environmentalScoreMap.get(environmentalScore.getConfidentialityRequirement());
            float mc= CvssScore.environmentalScoreMap.get(environmentalScore.getModifiedConfidentiality());
            float ir=CvssScore.environmentalScoreMap.get(environmentalScore.getIntegrityRequirement());
            float mi= CvssScore.environmentalScoreMap.get(environmentalScore.getModifiedIntegrity());
            float ar= CvssScore.environmentalScoreMap.get(environmentalScore.getAvailabilityRequirement());
            float ma= CvssScore.environmentalScoreMap.get(environmentalScore.getModifiedAvailability());
            float ecm= CvssScore.temporalScoreMap.get(temporalScore.getExploitCodeMaturity());
            float rl= CvssScore.temporalScoreMap.get(temporalScore.getRemediationLevel());
            float rc=CvssScore.temporalScoreMap.get(temporalScore.getReportConfidence());
             float miss= (float)Math.min(1-((1-cr*mc)*(1-ir*mi)*(1-ar*ma)),0.915);
        if (environmentalScore.getModifiedScope().equals("U")){
            modifiedImpact= (float)(6.42*miss);
        }
        else if (environmentalScore.getModifiedScope().equals("C")){
            modifiedImpact= (float) ((7.52*(miss-0.029))-(3.25*(Math.pow((miss*0.9731-0.02),13))));
            if (mpr==0.62){
                mpr=(float)0.68;
            }
            else if(mpr==0.27){
                mpr= (float)0.5;
            }
        }
             float modifiedExploitability= (float)8.22*mav*mac*mpr*mui;
        if( modifiedImpact<=0){
            es=0;
        }
        else {
            if (environmentalScore.getModifiedScope().equals("U")){
                es= Math.min((modifiedImpact+modifiedExploitability), 10);
                es= es*ecm*rl*rc;
            }
            else if( environmentalScore.getModifiedScope().equals("C"))
                es= (float)Math.min((1.08*(modifiedImpact+modifiedExploitability)),10);
                es= es*ecm*rl*rc;
        }
        return es;

    }

}
