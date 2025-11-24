package com.lms.config;

import com.lms.entity.Permission;
import com.lms.entity.Role;
import com.lms.repository.PermissionRepository;
import com.lms.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {
    
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    
    @Override
    @Transactional
    public void run(String... args) {
        initializeRolesAndPermissions();
    }
    
    private void initializeRolesAndPermissions() {
        // Create permissions if they don't exist
        List<String> permissionNames = Arrays.asList(
                "view_courses", "enroll_courses", "create_courses",
                "manage_grades", "take_attendance", "view_reports",
                "manage_users", "system_settings"
        );

        for (String permName : permissionNames) {
            if (!permissionRepository.existsByPermissionName(permName)) {
                Permission permission = Permission.builder()
                        .permissionName(permName)
                        .permissionDescription("Permission to " + permName.replace("_", " "))
                        .module(permName.split("_")[1])
                        .build();
                permissionRepository.save(permission);
                log.info("Created permission: {}", permName);
            }
        }

        // Create roles if they don't exist
        createRoleIfNotExists("student", "Regular student user",
                Arrays.asList("view_courses", "enroll_courses"));
        createRoleIfNotExists("instructor", "Course instructor",
                Arrays.asList("view_courses", "create_courses", "manage_grades", "take_attendance", "view_reports"));
        createRoleIfNotExists("teaching_assistant", "Teaching Assistant",
                Arrays.asList("view_courses", "manage_grades", "take_attendance"));
        createRoleIfNotExists("admin", "System Administrator",
                Arrays.asList("view_courses", "enroll_courses", "create_courses", "manage_grades",
                             "take_attendance", "view_reports", "manage_users", "system_settings"));
    }

    private void createRoleIfNotExists(String roleName, String description, List<String> permissionNames) {
        if (!roleRepository.existsByRoleName(roleName)) {
            Role role = Role.builder()
                    .roleName(roleName)
                    .roleDescription(description)
                    .build();

            for (String permName : permissionNames) {
                permissionRepository.findByPermissionName(permName)
                        .ifPresent(role::addPermission);
            }

            roleRepository.save(role);
            log.info("Created role: {} with {} permissions", roleName, permissionNames.size());
        }
    }
}