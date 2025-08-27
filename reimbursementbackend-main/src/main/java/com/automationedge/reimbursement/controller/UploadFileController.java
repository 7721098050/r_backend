package com.automationedge.reimbursement.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
public class UploadFileController {

    private static final Logger log = LoggerFactory.getLogger(UploadFileController.class);

    @Value("${file.upload-dir}")
    private String uploadDir;

    @PostMapping("/uploaddoc")
    public ResponseEntity<Map<String, String>> uploadFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("tenant_id") String tenantId) {

        Map<String, String> response = new HashMap<>();

        try {

            log.info("File upload request received. tenant_id={}, originalFilename={}", tenantId, file.getOriginalFilename());

            // Create tenant-specific folder inside uploadDir
            File tenantFolder = new File(uploadDir + File.separator + tenantId);
            if (!tenantFolder.exists()) {
                tenantFolder.mkdirs();
                log.debug("Created tenant folder: {}", tenantFolder.getAbsolutePath());
            }

            // Extract original filename
            String originalFilename = file.getOriginalFilename();
            String baseName = originalFilename;
            String extension = "";

            int dotIndex = originalFilename.lastIndexOf('.');
            if (dotIndex != -1) {
                baseName = originalFilename.substring(0, dotIndex);
                extension = originalFilename.substring(dotIndex); // includes "."
            }

            // Generate unique filename with original name + UUID
            String uniqueFilename = baseName + "_" + UUID.randomUUID().toString() + extension;

            // Full path to save file
            String filePath = tenantFolder.getAbsolutePath() + File.separator + uniqueFilename;
            file.transferTo(new File(filePath));
            log.info("File successfully uploaded. Saved at {}", filePath);

            // Build relative path for response
            String folderName = Paths.get(uploadDir).getFileName().toString();
            String relativePath = folderName + "/" + tenantId + "/" + uniqueFilename;

            // Prepare response
            response.put("status", "success");
            response.put("filepath", relativePath.replace("\\", "/"));
            response.put("stored_filename", uniqueFilename);
            response.put("tenant_id", tenantId);

            return ResponseEntity.ok(response);

        } catch (IOException e) {
            log.error("File upload failed for tenant_id={} filename={}. Error: {}", tenantId, file.getOriginalFilename(), e.getMessage(), e);
            response.put("status", "error");
            response.put("message", "File upload failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}
