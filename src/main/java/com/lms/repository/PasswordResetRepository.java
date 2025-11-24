package com.lms.repository;

import com.lms.entity.PasswordReset;
import com.lms.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface PasswordResetRepository extends JpaRepository<PasswordReset, Long> {
    
    Optional<PasswordReset> findByResetToken(String resetToken);
    
    @Query("SELECT pr FROM PasswordReset pr WHERE pr.resetToken = :token AND pr.used = false AND pr.expiresAt > :now")
    Optional<PasswordReset> findValidResetToken(String token, LocalDateTime now);
    
    @Modifying
    @Query("UPDATE PasswordReset pr SET pr.used = true WHERE pr.user = :user AND pr.used = false")
    void invalidateUserTokens(User user);
    
    @Modifying
    @Query("DELETE FROM PasswordReset pr WHERE pr.expiresAt < :now OR pr.used = true")
    void deleteExpiredOrUsedTokens(LocalDateTime now);
}