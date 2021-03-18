package com.example.cvssScore.dao;

import com.example.cvssScore.model.CvssScore;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Cvssrepo extends JpaRepository<CvssScore, String> {
}
