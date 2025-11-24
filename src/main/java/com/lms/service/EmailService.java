package com.lms.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {
    
    private final JavaMailSender mailSender;
    
    @Value("${app.frontend.url}")
    private String frontendUrl;
    
    @Value("${spring.mail.username}")
    private String fromEmail;
    
    @Async
    public void sendVerificationEmail(String to, String token, String userName) {
        try {
            String verificationLink = frontendUrl + "/verify-email?token=" + token;
            
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject("Verify Your Email - LMS Platform");
            message.setText(String.format(
                    "Hello %s,\n\n" +
                    "Thank you for registering with our LMS platform!\n\n" +
                    "Please click the link below to verify your email address:\n" +
                    "%s\n\n" +
                    "This link will expire in 24 hours.\n\n" +
                    "If you didn't create an account, please ignore this email.\n\n" +
                    "Best regards,\n" +
                    "LMS Team",
                    userName, verificationLink
            ));
            
            mailSender.send(message);
            log.info("Verification email sent to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send verification email to: {}", to, e);
        }
    }
    
    @Async
    public void sendPasswordResetEmail(String to, String token, String userName) {
        try {
            String resetLink = frontendUrl + "/reset-password?token=" + token;
            
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject("Password Reset Request - LMS Platform");
            message.setText(String.format(
                    "Hello %s,\n\n" +
                    "We received a request to reset your password.\n\n" +
                    "Please click the link below to reset your password:\n" +
                    "%s\n\n" +
                    "This link will expire in 1 hour.\n\n" +
                    "If you didn't request a password reset, please ignore this email or contact support if you have concerns.\n\n" +
                    "Best regards,\n" +
                    "LMS Team",
                    userName, resetLink
            ));
            
            mailSender.send(message);
            log.info("Password reset email sent to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send password reset email to: {}", to, e);
        }
    }
    
    @Async
    public void sendWelcomeEmail(String to, String userName) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject("Welcome to LMS Platform!");
            message.setText(String.format(
                    "Hello %s,\n\n" +
                    "Welcome to our Learning Management System!\n\n" +
                    "Your account has been successfully created and verified.\n\n" +
                    "You can now log in and start exploring our platform.\n\n" +
                    "Best regards,\n" +
                    "LMS Team",
                    userName
            ));
            
            mailSender.send(message);
            log.info("Welcome email sent to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send welcome email to: {}", to, e);
        }
    }
}