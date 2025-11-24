package com.lms.repository;

import com.lms.entity.TwoFactorAuth;
import com.lms.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface TwoFactorAuthRepository extends JpaRepository<TwoFactorAuth, Long> {
    
    Optional<TwoFactorAuth> findByUser(User user);
    
    boolean existsByUser(User user);
}