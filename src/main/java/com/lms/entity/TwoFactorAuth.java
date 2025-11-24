package com.lms.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import java.time.LocalDateTime;

@Entity
@Table(name = "two_factor_auth")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TwoFactorAuth {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "auth_id")
    private Long authId;
    
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;
    
    @Column(name = "secret_key", nullable = false, length = 255)
    private String secretKey;
    
    @Column(nullable = false)
    private Boolean enabled = false;
    
    @Column(name = "backup_codes", columnDefinition = "JSON")
    private String backupCodes;
    
    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;
    
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}