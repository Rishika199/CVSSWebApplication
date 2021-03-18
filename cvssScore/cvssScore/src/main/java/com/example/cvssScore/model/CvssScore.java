package com.example.cvssScore.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.stereotype.Component;

import java.util.HashMap;

@Data
@Component
public class CvssScore {
    @Id
    private String cvssId;
    private BaseScore baseScore;
    private TemporalScore temporalScore;
    private EnvironmentalScore environmentalScore;
   static public HashMap<String,Float> baseScoreMap;
   static public HashMap<String,Float> temporalScoreMap;
   static public HashMap<String,Float> environmentalScoreMap;

   static {
       baseScoreMap= new HashMap<>(32);
       temporalScoreMap= new HashMap<>(32);
       environmentalScoreMap = new HashMap<>(32);
       baseScoreMap.put("AVN",(float)0.85);
       baseScoreMap.put("AVA",(float)0.62);
       baseScoreMap.put("AVL",(float)0.55);
       baseScoreMap.put("AVP",(float)0.2);
       baseScoreMap.put("ACL", (float)0.77);
       baseScoreMap.put("ACH", (float)0.44);
       baseScoreMap.put("PRN", (float)0.85);
       baseScoreMap.put("PRL", (float)0.62);
       baseScoreMap.put("PRH", (float)0.27);
       baseScoreMap.put("URN", (float)0.85);
       baseScoreMap.put("URR", (float)0.62);
       baseScoreMap.put("CIAH", (float)0.56);
       baseScoreMap.put("CIAL", (float)0.22);
       baseScoreMap.put("CIAN", (float)0);
       temporalScoreMap.put("ECMN", (float)1);
       temporalScoreMap.put("ECMH", (float)1);
       temporalScoreMap.put("ECMF", (float)0.97);
       temporalScoreMap.put("ECMPC", (float)0.94);
       temporalScoreMap.put("ECMU", (float)0.91);
       temporalScoreMap.put("RLN", (float)1);
       temporalScoreMap.put("RLU", (float)1);
       temporalScoreMap.put("RLW", (float)0.97);
       temporalScoreMap.put("RLTF", (float)0.96);
       temporalScoreMap.put("RLOF", (float)0.95);
       temporalScoreMap.put("RCN", (float)1);
       temporalScoreMap.put("RCC", (float)1);
       temporalScoreMap.put("RCR", (float)0.96);
       temporalScoreMap.put("RCU", (float)0.92);
       environmentalScoreMap.put("CIARN", (float)1);
       environmentalScoreMap.put("CIARH", (float)1.5);
       environmentalScoreMap.put("CIARM", (float)1);
       environmentalScoreMap.put("CIARL", (float)0.5);
       environmentalScoreMap.put("MAVN",(float)0.85);
       environmentalScoreMap.put("MAVA",(float)0.62);
       environmentalScoreMap.put("MAVL",(float)0.55);
       environmentalScoreMap.put("MAVP",(float)0.2);
       environmentalScoreMap.put("MACL", (float)0.77);
       environmentalScoreMap.put("MACH", (float)0.44);
       environmentalScoreMap.put("MPRN", (float)0.85);
       environmentalScoreMap.put("MPRL", (float)0.62);
       environmentalScoreMap.put("MPRH", (float)0.27);
       environmentalScoreMap.put("MURN", (float)0.85);
       environmentalScoreMap.put("MURR", (float)0.62);
       environmentalScoreMap.put("MCIAH", (float)0.56);
       environmentalScoreMap.put("MCIAL", (float)0.22);
       environmentalScoreMap.put("MCIAN", (float)0);


   }

}
