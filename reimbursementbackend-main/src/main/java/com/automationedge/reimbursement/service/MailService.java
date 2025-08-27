package com.automationedge.reimbursement.service;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MailService {

    private final JavaMailSender mailSender;

    public void sendOtpEmail(String to, String otp) {
        String subject = "Password Reset OTP - reimbursement";
        String text = "Dear User,\n\n" +
                "Your OTP for resetting the password is: " + otp + "\n" +
                "This OTP is valid for the next 10 minutes.\n\n" +
                "Please do not share this OTP with anyone for security reasons.\n\n" +
                "Regards,\n" +
                "reimbursement Support Team";

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);

        mailSender.send(message);
    }
}
