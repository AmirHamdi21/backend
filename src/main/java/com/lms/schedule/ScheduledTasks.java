package com.lms.schedule;

import com.lms.repository.PasswordResetRepository;
import com.lms.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
@Slf4j
public class ScheduledTasks {
    
    private final SessionRepository sessionRepository;
    private final PasswordResetRepository passwordResetRepository;
    
    /**
     * Clean up expired sessions every hour
     */
    @Scheduled(fixedRate = 3600000) // 1 hour
    @Transactional
    public void cleanUpExpiredSessions() {
        log.info("Starting expired sessions cleanup");
        try {
            sessionRepository.deleteExpiredSessions(LocalDateTime.now());
            log.info("Expired sessions cleanup completed");
        } catch (Exception e) {
            log.error("Error during expired sessions cleanup", e);
        }
    }
    
    /**
     * Clean up expired password reset tokens every day
     */
    @Scheduled(cron = "0 0 2 * * *") // Every day at 2 AM
    @Transactional
    public void cleanUpExpiredPasswordResets() {
        log.info("Starting expired password resets cleanup");
        try {
            passwordResetRepository.deleteExpiredOrUsedTokens(LocalDateTime.now());
            log.info("Expired password resets cleanup completed");
        } catch (Exception e) {
            log.error("Error during expired password resets cleanup", e);
        }
    }
}