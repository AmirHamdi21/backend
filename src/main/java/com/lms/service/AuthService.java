package com.lms.service;

import com.lms.dto.*;
import com.lms.entity.*;
import com.lms.exception.*;
import com.lms.repository.*;
import com.lms.security.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

        private final UserRepository userRepository;
        private final RoleRepository roleRepository;
        private final SessionRepository sessionRepository;
        private final PasswordResetRepository passwordResetRepository;
        private final PasswordEncoder passwordEncoder;
        private final AuthenticationManager authenticationManager;
        private final JwtTokenProvider tokenProvider;
        private final EmailService emailService;

        private static final int TOKEN_LENGTH = 32;
        private static final long PASSWORD_RESET_EXPIRY_HOURS = 1;

        /**
         * Register a new user
         */
        @Transactional
        public AuthResponse register(RegisterRequest request) {
                // Check if email already exists
                if (userRepository.existsByEmailAndNotDeleted(request.getEmail())) {
                        throw new EmailAlreadyExistsException("Email already in use: " + request.getEmail());
                }

                // Create new user
                User user = User.builder()
                                .email(request.getEmail().toLowerCase())
                                .passwordHash(passwordEncoder.encode(request.getPassword()))
                                .firstName(request.getFirstName())
                                .lastName(request.getLastName())
                                .phone(request.getPhone())
                                .campusId(request.getCampusId())
                                .status(User.UserStatus.pending)
                                .emailVerified(false)
                                .build();

                // Assign default student role
                Role studentRole = roleRepository.findByRoleName("student")
                                .orElseThrow(() -> new RuntimeException("Default student role not found"));
                user.addRole(studentRole);

                user = userRepository.save(user);

                // Fetch the user again with roles loaded to avoid lazy loading issues
                user = userRepository.findById(user.getUserId())
                                .orElseThrow(() -> new RuntimeException("User not found after save"));

                log.info("New user registered: {}", user.getEmail());

                // Send verification email
                String verificationToken = generateSecureToken();
                // For simplicity, encode email as token
                String encodedEmail = Base64.getUrlEncoder().encodeToString(user.getEmail().getBytes());
                emailService.sendVerificationEmail(user.getEmail(), encodedEmail,
                                user.getFirstName() + " " + user.getLastName());

                // Generate tokens using CustomUserDetails
                CustomUserDetails userDetails = CustomUserDetails.build(user);
                Authentication authentication = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());

                String accessToken = tokenProvider.generateAccessToken(authentication);
                String refreshToken = tokenProvider.generateRefreshToken(authentication);

                // Create session
                createSession(user, refreshToken, null, null);

                return new AuthResponse(
                                accessToken,
                                refreshToken,
                                tokenProvider.getExpirationTime(),
                                convertToDto(user));
        }

        /**
         * Authenticate user and generate tokens
         */
        @Transactional
        public AuthResponse login(LoginRequest request) {
                // Authenticate user
                Authentication authentication = authenticationManager.authenticate(
                                new UsernamePasswordAuthenticationToken(
                                                request.getEmail().toLowerCase(),
                                                request.getPassword()));

                SecurityContextHolder.getContext().setAuthentication(authentication);

                // Get user
                User user = userRepository.findByEmailAndNotDeleted(request.getEmail().toLowerCase())
                                .orElseThrow(() -> new InvalidCredentialsException("Invalid credentials"));

                // Check if email is verified
                if (!user.getEmailVerified()) {
                        throw new EmailNotVerifiedException("Please verify your email before logging in");
                }

                // Check account status
                if (user.getStatus() != User.UserStatus.active) {
                        throw new AccountSuspendedException("Account is not active. Status: " + user.getStatus());
                }

                // Update last login
                user.updateLastLogin();
                userRepository.save(user);

                // Generate tokens
                String accessToken = tokenProvider.generateAccessToken(authentication);
                String refreshToken = tokenProvider.generateRefreshToken(authentication);

                // Create session
                createSession(user, refreshToken, null, null);

                log.info("User logged in successfully: {}", user.getEmail());

                return new AuthResponse(
                                accessToken,
                                refreshToken,
                                tokenProvider.getExpirationTime(),
                                convertToDto(user));
        }

        /**
         * Logout user and invalidate session
         */
        @Transactional
        public MessageResponse logout() {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

                User user = userRepository.findById(userDetails.getUserId())
                                .orElseThrow(() -> new UserNotFoundException("User not found"));

                // Invalidate all sessions
                sessionRepository.deleteAllByUser(user);

                log.info("User logged out: {}", user.getEmail());

                return MessageResponse.success("Logged out successfully");
        }

        /**
         * Refresh access token using refresh token
         */
        @Transactional
        public AuthResponse refreshToken(RefreshTokenRequest request) {
                String refreshToken = request.getRefreshToken();

                // Validate refresh token
                if (!tokenProvider.validateToken(refreshToken) || !tokenProvider.isRefreshToken(refreshToken)) {
                        throw new TokenExpiredException("Invalid or expired refresh token");
                }

                // Get user from token
                String email = tokenProvider.getEmailFromToken(refreshToken);
                User user = userRepository.findByEmailAndNotDeleted(email)
                                .orElseThrow(() -> new UserNotFoundException("User not found"));

                // Verify session exists
                Session session = sessionRepository.findBySessionToken(refreshToken)
                                .orElseThrow(() -> new TokenExpiredException("Session not found"));

                if (session.isExpired()) {
                        sessionRepository.delete(session);
                        throw new TokenExpiredException("Session expired");
                }

                // Generate new access token
                Authentication authentication = new UsernamePasswordAuthenticationToken(
                                CustomUserDetails.build(user), null, CustomUserDetails.build(user).getAuthorities());

                String newAccessToken = tokenProvider.generateAccessToken(authentication);

                return new AuthResponse(
                                newAccessToken,
                                refreshToken,
                                tokenProvider.getExpirationTime(),
                                convertToDto(user));
        }

        /**
         * Request password reset
         */
        @Transactional
        public MessageResponse forgotPassword(ForgotPasswordRequest request) {
                User user = userRepository.findByEmailAndNotDeleted(request.getEmail().toLowerCase())
                                .orElse(null);

                // Always return success to prevent email enumeration
                if (user == null) {
                        log.warn("Password reset requested for non-existent email: {}", request.getEmail());
                        return MessageResponse.success("If the email exists, a reset link has been sent");
                }

                // Invalidate existing tokens
                passwordResetRepository.invalidateUserTokens(user);

                // Generate reset token
                String resetToken = generateSecureToken();
                LocalDateTime expiresAt = LocalDateTime.now().plusHours(PASSWORD_RESET_EXPIRY_HOURS);

                PasswordReset passwordReset = PasswordReset.builder()
                                .user(user)
                                .resetToken(resetToken)
                                .expiresAt(expiresAt)
                                .used(false)
                                .build();

                passwordResetRepository.save(passwordReset);

                // Send reset email
                emailService.sendPasswordResetEmail(user.getEmail(), resetToken,
                                user.getFirstName() + " " + user.getLastName());

                log.info("Password reset requested for: {}", user.getEmail());

                return MessageResponse.success("If the email exists, a reset link has been sent");
        }

        /**
         * Reset password with token
         */
        @Transactional
        public MessageResponse resetPassword(ResetPasswordRequest request) {
                // Find valid reset token
                PasswordReset passwordReset = passwordResetRepository
                                .findValidResetToken(request.getToken(), LocalDateTime.now())
                                .orElseThrow(() -> new TokenExpiredException("Invalid or expired reset token"));

                User user = passwordReset.getUser();

                // Update password
                user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
                userRepository.save(user);

                // Mark token as used
                passwordReset.setUsed(true);
                passwordReset.setUsedAt(LocalDateTime.now());
                passwordResetRepository.save(passwordReset);

                // Invalidate all sessions
                sessionRepository.deleteAllByUser(user);

                log.info("Password reset successfully for: {}", user.getEmail());

                return MessageResponse.success("Password reset successfully");
        }

        /**
         * Verify email with token
         */
        @Transactional
        public MessageResponse verifyEmail(VerifyEmailRequest request) {
                // In production, implement email verification token storage
                // For now, decode token to get email
                String email = decodeVerificationToken(request.getToken());

                User user = userRepository.findByEmailAndNotDeleted(email)
                                .orElseThrow(() -> new UserNotFoundException("User not found"));

                if (user.getEmailVerified()) {
                        return MessageResponse.success("Email already verified");
                }

                user.setEmailVerified(true);
                user.setStatus(User.UserStatus.active);
                userRepository.save(user);

                log.info("Email verified for: {}", user.getEmail());

                return MessageResponse.success("Email verified successfully");
        }

        /**
         * Get current user info
         */
        @Transactional(readOnly = true)
        public UserDto getCurrentUser() {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

                User user = userRepository.findById(userDetails.getUserId())
                                .orElseThrow(() -> new UserNotFoundException("User not found"));

                return convertToDto(user);
        }

        // Helper methods

        private void createSession(User user, String refreshToken, String ipAddress, String userAgent) {
                LocalDateTime expiresAt = LocalDateTime.now().plusDays(7);

                Session session = Session.builder()
                                .sessionToken(refreshToken)
                                .ipAddress(ipAddress)
                                .userAgent(userAgent)
                                .deviceType(Session.DeviceType.WEB)
                                .expiresAt(expiresAt)
                                .build();

                session.setUser(user); // Set user reference
                sessionRepository.save(session);
        }

        private String generateSecureToken() {
                SecureRandom random = new SecureRandom();
                byte[] bytes = new byte[TOKEN_LENGTH];
                random.nextBytes(bytes);
                return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        }

        private String decodeVerificationToken(String token) {
                // Implement proper token verification in production
                // This is a simplified version
                return new String(Base64.getUrlDecoder().decode(token));
        }

        private UserDto convertToDto(User user) {
                Set<String> roles = user.getRoles().stream()
                                .map(Role::getRoleName)
                                .collect(Collectors.toSet());

                Set<String> permissions = user.getRoles().stream()
                                .flatMap(role -> role.getPermissions().stream())
                                .map(Permission::getPermissionName)
                                .collect(Collectors.toSet());

                return UserDto.builder()
                                .userId(user.getUserId())
                                .email(user.getEmail())
                                .firstName(user.getFirstName())
                                .lastName(user.getLastName())
                                .phone(user.getPhone())
                                .profilePictureUrl(user.getProfilePictureUrl())
                                .campusId(user.getCampusId())
                                .status(user.getStatus().name())
                                .emailVerified(user.getEmailVerified())
                                .lastLoginAt(user.getLastLoginAt())
                                .createdAt(user.getCreatedAt())
                                .roles(roles)
                                .permissions(permissions)
                                .build();
        }
}