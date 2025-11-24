package com.lms.repository;

import com.lms.entity.Session;
import com.lms.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface SessionRepository extends JpaRepository<Session, Long> {
    
    Optional<Session> findBySessionToken(String sessionToken);
    
    List<Session> findByUser(User user);
    
    @Query("SELECT s FROM Session s WHERE s.user = :user AND s.expiresAt > :now")
    List<Session> findActiveSessionsByUser(User user, LocalDateTime now);
    
    @Modifying
    @Query("DELETE FROM Session s WHERE s.user = :user")
    void deleteAllByUser(User user);
    
    @Modifying
    @Query("DELETE FROM Session s WHERE s.expiresAt < :now")
    void deleteExpiredSessions(LocalDateTime now);
}