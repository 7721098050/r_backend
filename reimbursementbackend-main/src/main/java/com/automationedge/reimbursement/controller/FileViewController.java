package com.automationedge.reimbursement.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;

@RestController
public class FileViewController {

    private static final Logger logger = LoggerFactory.getLogger(FileViewController.class);

    @Value("${file.upload-dir}")
    private String uploadDir;

    @CrossOrigin(origins = "http://localhost:3000")
    @GetMapping("/files/{tenantId}/{filename:.+}")
    public ResponseEntity<Resource> serveFile(
            @PathVariable String tenantId,
            @PathVariable String filename) {
        try {
            // Prepend tenantId folder to existing uploadDir
            Path filePath = Paths.get(uploadDir, tenantId).resolve(filename).normalize();

            logger.info("File requested: {}", filePath);

            if (!Files.exists(filePath)) {
                logger.warn("File not found: {}", filePath);
                return ResponseEntity.notFound().build();
            }

            if (!Files.isReadable(filePath)) {
                logger.error("File not readable: {}", filePath);
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }

            Resource resource = new UrlResource(filePath.toUri());

            logger.info("Serving file: {}", filePath);

            return ResponseEntity.ok()
                    .header("Content-Disposition", "inline; filename=\"" + filename + "\"")
                    .body(resource);

        } catch (Exception e) {
            logger.error("Exception while serving file: {}", filename, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
