package dev.webstarter.system.service;

/**
 * Outbound port for invalidating transport credentials after an identity epoch changes.
 * The system module owns the identity transaction and never depends on its security adapter.
 */
public interface IdentitySecurityLifecyclePort {

    void userSecurityEpochAdvanced(
            Long userId,
            String username,
            long securityEpoch,
            String reason);
}
