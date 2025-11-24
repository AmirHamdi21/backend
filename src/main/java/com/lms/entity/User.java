package com.lms.entity;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userId;
    
    @Column(nullable = false, unique = true, length = 255)
    private String email;
    
    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;
    
    @Column(name = "first_name", nullable = false, length = 100)
    private String firstName;
    
    @Column(name = "last_name", nullable = false, length = 100)
    private String lastName;
    
    @Column(length = 20)
    private String phone;
    
    @Column(name = "profile_picture_url", length = 500)
    private String profilePictureUrl;
    
    @Column(name = "campus_id")
    private Long campusId;
    
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private UserStatus status = UserStatus.pending;
    
    @Column(name = "email_verified")
    private Boolean emailVerified = false;
    
    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;
    
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
    
    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;
    
    @ManyToMany(fetch = FetchType.EAGER, cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    @ToString.Exclude
    @JsonManagedReference
    private Set<Role> roles = new HashSet<>();
    
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    @ToString.Exclude
    @JsonManagedReference
    private Set<Session> sessions = new HashSet<>();
    
    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @ToString.Exclude
    private TwoFactorAuth twoFactorAuth;
    
    @Transient
    public boolean isDeleted() {
        return deletedAt != null;
    }
    
    public void updateLastLogin() {
        this.lastLoginAt = LocalDateTime.now();
    }
    
    public void addRole(Role role) {
        this.roles.add(role);
        role.getUsers().add(this);
    }
    
    public void removeRole(Role role) {
        this.roles.remove(role);
        role.getUsers().remove(this);
    }
    
    public enum UserStatus {
        active, inactive, suspended, pending
    }
}