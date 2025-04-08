package com.example.Vulnerablity.Scanner.repository;

import com.example.Vulnerablity.Scanner.model.ScanHistory;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanHistoryRepository extends CrudRepository<ScanHistory, String> {
    List<ScanHistory> findByTarget(String target);
    List<ScanHistory> findAll();
}