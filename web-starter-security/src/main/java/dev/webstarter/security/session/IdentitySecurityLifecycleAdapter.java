package dev.webstarter.security.session;

import java.time.Instant;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import dev.webstarter.security.persistence.mapper.AccessCredentialMapper;
import dev.webstarter.security.token.CredentialType;
import dev.webstarter.system.service.IdentitySecurityLifecyclePort;

@Component
public final class IdentitySecurityLifecycleAdapter implements IdentitySecurityLifecyclePort {

    private static final Log LOGGER = LogFactory.getLog(IdentitySecurityLifecycleAdapter.class);

    private final AccessCredentialMapper credentialMapper;
    private final WebSessionManagementService sessionService;
    private final TransactionTemplate cleanupTransaction;

    public IdentitySecurityLifecycleAdapter(
            AccessCredentialMapper credentialMapper,
            WebSessionManagementService sessionService,
            PlatformTransactionManager transactionManager) {
        this.credentialMapper = credentialMapper;
        this.sessionService = sessionService;
        this.cleanupTransaction = new TransactionTemplate(transactionManager);
        this.cleanupTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @Override
    public void userSecurityEpochAdvanced(
            Long userId,
            String username,
            long securityEpoch,
            String reason) {
        Runnable cleanup = () -> cleanup(userId, username, reason);
        if (TransactionSynchronizationManager.isSynchronizationActive()
                && TransactionSynchronizationManager.isActualTransactionActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    runSafely(cleanup);
                }
            });
            return;
        }
        runSafely(cleanup);
    }

    private void cleanup(Long userId, String username, String reason) {
        try {
            cleanupTransaction.executeWithoutResult(status -> credentialMapper.revokeBySubject(
                    CredentialType.PERSONAL_ACCESS_TOKEN.name(), userId, reason, Instant.now()));
        }
        finally {
            sessionService.revokeAllForPrincipal(username);
        }
    }

    private static void runSafely(Runnable cleanup) {
        try {
            cleanup.run();
        }
        catch (RuntimeException exception) {
            // Identity epochs are the authoritative rejection mechanism. Cleanup is defense in depth.
            LOGGER.error("Post-commit identity credential cleanup failed", exception);
        }
    }
}
