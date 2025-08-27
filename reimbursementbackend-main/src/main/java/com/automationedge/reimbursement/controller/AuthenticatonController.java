package com.automationedge.reimbursement.controller;

import com.automationedge.platform.security.jwt.JwtUtil;
import com.automationedge.reimbursement.service.MailService;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RequestMapping("/auth")
@RequiredArgsConstructor
@RestController
public class AuthenticatonController {

    private final JdbcTemplate jdbcTemplate;
    private final JwtUtil jwtUtil;
    private final MailService mailService; // Injected service for sending emails
    private static final Logger log = LoggerFactory.getLogger(AuthenticatonController.class);

    // ---------------- Existing Login API -----------------
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> payload) {
        String grantType = payload.get("grant_type");

        if (grantType == null || grantType.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "grant_type is required"));
        }

        try {
            // ------------------- Case 1: Password grant -------------------
            if ("password".equalsIgnoreCase(grantType)) {
                String email = payload.get("email");
                String password = payload.get("password");

                if (email == null || email.isBlank() || password == null || password.isBlank()) {
                    log.warn("Login attempt failed: missing email or password");
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(Map.of("error", "Email and password are required"));
                }

                log.info("Login attempt for email={}", email);

                Map<String, Object> user = jdbcTemplate.queryForMap(
                        "SELECT * FROM reimb_users WHERE email = ?", email
                );

                // Check if user is active
                Boolean isActive = (Boolean) user.get("is_active");
                if (Boolean.FALSE.equals(isActive)) {
                    log.warn("Login attempt for inactive account: {}", email);
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of("error", "Your account is currently inactive. Please contact your administrator."));
                }

                String storedHash = (String) user.get("user_password");
                if (!password.equals(storedHash)) {
                    log.warn("Login failed: invalid credentials for email={}", email);
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("error", "Invalid email or password"));
                }

                String token = jwtUtil.createToken(
                        email,
                        "",
                        Map.of(
                                "user_id", user.get("id"),
                                "email", user.get("email"),
                                "roles", user.get("user_role"),
                                "tenant_id", user.get("tenant_id")
                        )
                );

                log.info("Login successful for email={}, userRole={}", email, user.get("user_role"));
                return ResponseEntity.ok(Map.of("token", token));
            }

            // ------------------- Case 2: Refresh token grant -------------------
            else if ("refresh_token".equalsIgnoreCase(grantType)) {
                String refreshToken = payload.get("refresh_token");
                if (refreshToken == null || refreshToken.isBlank()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(Map.of("error", "refresh_token is required"));
                }

                // Extract user info from refresh token
                String email = jwtUtil.extractUsername(refreshToken);

                // Validate refresh token
                if (!jwtUtil.validateToken(refreshToken, email)) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("error", "Invalid or expired refresh token"));
                }
                Map<String, Object> user = jdbcTemplate.queryForMap(
                        "SELECT * FROM reimb_users WHERE email = ?", email
                );

                String token = jwtUtil.createToken(
                        email,
                        "",
                        Map.of(
                                "user_id", user.get("id"),
                                "email", user.get("email"),
                                "roles", user.get("user_role"),
                                "tenant_id", user.get("tenant_id")
                        )
                );

                log.info("Access token refreshed for email={}", email);
                return ResponseEntity.ok(Map.of("token", token));
            }

            // ------------------- Unsupported grant type -------------------
            else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", "Unsupported grant_type"));
            }

        } catch (EmptyResultDataAccessException ex) {
            log.warn("Login failed: no user found");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid email or password"));
        } catch (Exception e) {
            log.error("Unexpected error during login", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Something went wrong. Please try again later."));
        }
    }

    // ---------------- Forgot Password Flow -----------------

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        if (email == null || email.isBlank()) {
            log.warn("Forgot password attempted without providing email");
            return ResponseEntity.badRequest().body(Map.of("error", "Email is required"));
        }

        try {
            log.info("Processing forgot-password request for email={}", email);

            // Check if user exists and fetch is_active
            Map<String, Object> user = jdbcTemplate.queryForMap(
                    "SELECT is_active FROM reimb_users WHERE email = ?", email
            );

            if (user == null) {
                log.warn("Forgot-password requested for unregistered email={}", email);
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("error", "Email not registered"));
            }

            // Check if user is active
            Boolean isActive = (Boolean) user.get("is_active");
            if (Boolean.FALSE.equals(isActive)) {
                log.warn("Forgot-password attempted for inactive account, email={}", email);
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("error", "Your account is inactive. You cannot reset your password."));
            }

            // Generate OTP
            String otp = String.valueOf((int) (Math.random() * 900000) + 100000);
            LocalDateTime expiry = LocalDateTime.now().plusMinutes(10);

            jdbcTemplate.update(
                    "INSERT INTO reimb_password_reset (email, otp, expires_at, used_flag) VALUES (?, ?, ?, false)",
                    email, otp, expiry
            );

            log.debug("Generated OTP={} with expiry={}", otp, expiry); // DEBUG only

            mailService.sendOtpEmail(email, otp);
            log.info("OTP successfully sent to email={}", email);

            return ResponseEntity.ok(Map.of("message", "OTP sent to your email"));
        } catch (Exception e) {
            log.error("Error occurred during forgot-password for email={}", email, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to process forgot password"));
        }
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        String otp = payload.get("otp");

        if (email == null || otp == null) {
            log.warn("Verify-OTP failed: missing email or otp in request payload");
            return ResponseEntity.badRequest().body(Map.of("error", "Email and OTP are required"));
        }

        try {
            log.info("Processing verify-otp request for email={}", email);

            Map<String, Object> record = jdbcTemplate.queryForMap(
                    "SELECT * FROM reimb_password_reset WHERE email = ? AND otp = ? AND used_flag = false AND expires_at > now() ORDER BY created_at DESC LIMIT 1",
                    email, otp
            );

            String resetToken = UUID.randomUUID().toString();
            log.debug("OTP verified for email={} | generated resetToken={}", email, resetToken);

            jdbcTemplate.update(
                    "UPDATE reimb_password_reset SET reset_token = ?, used_flag = true WHERE id = ?",
                    UUID.fromString(resetToken), record.get("id")
            );

            log.info("Reset token successfully created for email={}", email);

            return ResponseEntity.ok(Map.of("reset_token", resetToken));

        } catch (EmptyResultDataAccessException ex) {
            log.warn("Verify-OTP failed for email={} with otp={} | Reason: invalid or expired", email, otp);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "Invalid or expired OTP"));
        } catch (Exception e) {
            log.error("Unexpected error while verifying OTP for email={}", email, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to verify OTP"));
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> payload) {
        String resetToken = payload.get("reset_token");
        String newPassword = payload.get("new_password");

        if (resetToken == null || newPassword == null) {
            log.warn("Reset-password failed: missing reset_token or new_password in request payload");
            return ResponseEntity.badRequest().body(Map.of("error", "Reset token and new password are required"));
        }

        try {
            log.info("Processing reset-password request with resetToken={}", resetToken);

            // 1. Validate token
            Map<String, Object> record = jdbcTemplate.queryForMap(
                    "SELECT * FROM reimb_password_reset WHERE reset_token = ? AND expires_at > now()",
                    UUID.fromString(resetToken)
            );

            String email = (String) record.get("email");

            // 2. Check if user is active
            Map<String, Object> user = jdbcTemplate.queryForMap(
                    "SELECT is_active FROM reimb_users WHERE email = ?", email
            );
            Boolean isActive = (Boolean) user.get("is_active");
            if (Boolean.FALSE.equals(isActive)) {
                log.warn("Reset-password attempted for inactive account, email={}", email);
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("error", "Your account is inactive. You cannot reset your password."));
            }

            // 3. Update password
            jdbcTemplate.update("UPDATE reimb_users SET user_password = ? WHERE email = ?", newPassword, email);
            log.debug("Password updated successfully in reimb_users for email={}", email);

            // 4. Invalidate token
            jdbcTemplate.update("DELETE FROM reimb_password_reset WHERE id = ?", record.get("id"));
            log.info("Password reset completed and token invalidated for email={}", email);

            return ResponseEntity.ok(Map.of("message", "Password reset successful"));

        } catch (EmptyResultDataAccessException ex) {
            log.warn("Reset-password failed with invalid or expired token={}", resetToken);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "Invalid or expired reset token"));
        } catch (Exception e) {
            log.error("Unexpected error while resetting password with token={}", resetToken, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to reset password"));
        }
    }
}
