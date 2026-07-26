package dev.webstarter.security.session;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;

import dev.webstarter.security.token.TokenHasher;

/** Lists and revokes only a principal's sessions without exposing Redis session identifiers. */
public final class WebSessionManagementService {

    public static final String CLIENT_IP_ATTRIBUTE = "webstarter.client-ip";
    public static final String USER_AGENT_ATTRIBUTE = "webstarter.user-agent";
    private static final String REFERENCE_DOMAIN = "web-session:";

    private final FindByIndexNameSessionRepository<? extends Session> sessions;
    private final TokenHasher tokenHasher;

    public WebSessionManagementService(
            FindByIndexNameSessionRepository<? extends Session> sessions,
            TokenHasher tokenHasher) {
        this.sessions = sessions;
        this.tokenHasher = tokenHasher;
    }

    public List<SessionSummary> findByPrincipal(String principalName, String currentSessionId) {
        return sessions.findByPrincipalName(principalName).values().stream()
                .filter(session -> !session.isExpired())
                .map(session -> summary(session, currentSessionId))
                .sorted(Comparator.comparing(SessionSummary::lastAccessedAt).reversed())
                .toList();
    }

    public boolean revoke(String principalName, String opaqueReference) {
        if (opaqueReference == null || opaqueReference.isBlank()) {
            return false;
        }
        for (Map.Entry<String, ? extends Session> entry
                : sessions.findByPrincipalName(principalName).entrySet()) {
            if (constantTimeEquals(reference(entry.getValue().getId()), opaqueReference)) {
                sessions.deleteById(entry.getValue().getId());
                return true;
            }
        }
        return false;
    }

    public int revokeOtherSessions(String principalName, String currentSessionId) {
        int revoked = 0;
        for (Session session : sessions.findByPrincipalName(principalName).values()) {
            if (!session.getId().equals(currentSessionId)) {
                sessions.deleteById(session.getId());
                revoked++;
            }
        }
        return revoked;
    }

    public int revokeAllForPrincipal(String principalName) {
        int revoked = 0;
        for (Session session : sessions.findByPrincipalName(principalName).values()) {
            sessions.deleteById(session.getId());
            revoked++;
        }
        return revoked;
    }

    public String reference(String rawSessionId) {
        return tokenHasher.hash(REFERENCE_DOMAIN + rawSessionId);
    }

    private SessionSummary summary(Session session, String currentSessionId) {
        Instant expiresAt = session.getLastAccessedTime().plus(session.getMaxInactiveInterval());
        return new SessionSummary(
                reference(session.getId()),
                session.getId().equals(currentSessionId),
                session.getCreationTime(),
                session.getLastAccessedTime(),
                expiresAt,
                session.getAttribute(CLIENT_IP_ATTRIBUTE),
                session.getAttribute(USER_AGENT_ATTRIBUTE));
    }

    private static boolean constantTimeEquals(String expected, String supplied) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII),
                supplied.getBytes(StandardCharsets.US_ASCII));
    }

    public record SessionSummary(
            String reference,
            boolean current,
            Instant createdAt,
            Instant lastAccessedAt,
            Instant expiresAt,
            String ipAddress,
            String userAgent) {
    }
}
