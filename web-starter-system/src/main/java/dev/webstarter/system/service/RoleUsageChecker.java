package dev.webstarter.system.service;

/**
 * Extension point for modules that bind system roles to their own principals.
 * It keeps the system module independent from those modules while allowing a
 * role delete to preserve referential integrity across the modular monolith.
 */
@FunctionalInterface
public interface RoleUsageChecker {

    boolean isRoleInUse(Long roleId);
}
