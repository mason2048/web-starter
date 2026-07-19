package dev.webstarter.admin.bootstrap;

import java.time.LocalDateTime;
import java.util.Set;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import dev.webstarter.core.security.PasswordHasher;
import dev.webstarter.system.domain.SysRole;
import dev.webstarter.system.domain.SysUser;
import dev.webstarter.system.persistence.mapper.RoleMapper;
import dev.webstarter.system.persistence.mapper.UserMapper;
import dev.webstarter.system.persistence.mapper.UserRoleMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class BootstrapAdminInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapAdminInitializer.class);

    private final Environment environment;
    private final UserMapper userMapper;
    private final RoleMapper roleMapper;
    private final UserRoleMapper userRoleMapper;
    private final PasswordHasher passwordHasher;

    public BootstrapAdminInitializer(
            Environment environment,
            UserMapper userMapper,
            RoleMapper roleMapper,
            UserRoleMapper userRoleMapper,
            PasswordHasher passwordHasher) {
        this.environment = environment;
        this.userMapper = userMapper;
        this.roleMapper = roleMapper;
        this.userRoleMapper = userRoleMapper;
        this.passwordHasher = passwordHasher;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments arguments) {
        String username = trim(environment.getProperty("web-starter.bootstrap-admin.username"));
        String password = environment.getProperty("web-starter.bootstrap-admin.password");
        String displayName = defaultText(
                environment.getProperty("web-starter.bootstrap-admin.display-name"), "系统管理员");

        boolean usernamePresent = hasText(username);
        boolean passwordPresent = hasText(password);
        // The password is the one-time bootstrap switch. Compose may keep the
        // harmless username configured after operators remove the password.
        // In that state the initializer must become a no-op on every restart.
        if (!passwordPresent) {
            if (userMapper.selectCount(null) == 0) {
                log.warn("No users exist. Configure WEB_STARTER_BOOTSTRAP_ADMIN_USERNAME and "
                        + "WEB_STARTER_BOOTSTRAP_ADMIN_PASSWORD for the first startup");
            }
            return;
        }

        if (!usernamePresent) {
            throw new IllegalStateException(
                    "Bootstrap administrator username is required when the bootstrap password is configured");
        }

        if (username.length() > 64 || password.length() < 12 || password.startsWith("replace-with-")) {
            throw new IllegalStateException(
                    "Bootstrap administrator credentials do not meet the minimum policy");
        }

        SysUser existing = userMapper.selectOne(new LambdaQueryWrapper<SysUser>()
                .eq(SysUser::getUsername, username));
        if (existing != null) {
            log.info("Bootstrap administrator already exists; the configured password was not applied");
            return;
        }
        if (userMapper.selectCount(null) > 0) {
            throw new IllegalStateException(
                    "Bootstrap administrator is only created in a database without users");
        }

        SysRole adminRole = roleMapper.selectOne(new LambdaQueryWrapper<SysRole>()
                .eq(SysRole::getCode, "ADMIN"));
        if (adminRole == null) {
            throw new IllegalStateException("Seeded ADMIN role is missing");
        }

        LocalDateTime now = LocalDateTime.now();
        SysUser user = new SysUser();
        user.setUsername(username);
        user.setDisplayName(displayName);
        user.setPasswordHash(passwordHasher.hash(password));
        user.setStatus("ENABLED");
        user.setVersion(0);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        user.setDeleted(0);
        userMapper.insert(user);
        userRoleMapper.insertBatch(user.getId(), Set.of(adminRole.getId()));
        log.info("Bootstrap administrator created; remove the bootstrap password environment variable");
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static String trim(String value) {
        return value == null ? null : value.trim();
    }

    private static String defaultText(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }
}
