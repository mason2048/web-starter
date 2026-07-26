package dev.webstarter.security.session;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;

import dev.webstarter.security.token.TokenHasher;

class WebSessionManagementServiceTest {

    private static final String PEPPER = "0123456789abcdef0123456789abcdef";

    @Test
    void listsOpaqueReferencesAndNeverReturnsRawSessionIds() {
        InMemoryIndexedSessions repository = new InMemoryIndexedSessions();
        MapSession current = session("raw-current-session", "operator", "10.0.0.1");
        MapSession other = session("raw-other-session", "operator", "10.0.0.2");
        repository.save(current);
        repository.save(other);
        WebSessionManagementService service = service(repository);

        var summaries = service.findByPrincipal("operator", current.getId());

        assertThat(summaries).hasSize(2);
        assertThat(summaries).anyMatch(summary -> summary.current()
                && summary.ipAddress().equals("10.0.0.1"));
        assertThat(summaries).allSatisfy(summary -> {
            assertThat(summary.reference()).matches("[0-9a-f]{64}");
            assertThat(summary.reference()).doesNotContain("raw-");
        });
    }

    @Test
    void revokesOnlySessionsOwnedByTheAuthenticatedPrincipal() {
        InMemoryIndexedSessions repository = new InMemoryIndexedSessions();
        MapSession owned = session("owned-session", "operator", "10.0.0.1");
        MapSession foreign = session("foreign-session", "another-user", "10.0.0.2");
        repository.save(owned);
        repository.save(foreign);
        WebSessionManagementService service = service(repository);

        assertThat(service.revoke("operator", service.reference(foreign.getId()))).isFalse();
        assertThat(service.revoke("operator", service.reference(owned.getId()))).isTrue();

        assertThat(repository.findById(owned.getId())).isNull();
        assertThat(repository.findById(foreign.getId())).isNotNull();
    }

    private static WebSessionManagementService service(InMemoryIndexedSessions repository) {
        return new WebSessionManagementService(repository, new TokenHasher(PEPPER));
    }

    private static MapSession session(String id, String principal, String ip) {
        MapSession session = new MapSession(id);
        Instant now = Instant.now();
        session.setCreationTime(now.minusSeconds(3_600));
        session.setLastAccessedTime(now.minusSeconds(60));
        session.setMaxInactiveInterval(Duration.ofHours(8));
        session.setAttribute("test-principal", principal);
        session.setAttribute(WebSessionManagementService.CLIENT_IP_ATTRIBUTE, ip);
        session.setAttribute(WebSessionManagementService.USER_AGENT_ATTRIBUTE, "Test Browser");
        return session;
    }

    private static final class InMemoryIndexedSessions
            implements FindByIndexNameSessionRepository<MapSession> {

        private final Map<String, MapSession> sessions = new LinkedHashMap<>();

        @Override
        public MapSession createSession() {
            return new MapSession();
        }

        @Override
        public void save(MapSession session) {
            sessions.put(session.getId(), session);
        }

        @Override
        public MapSession findById(String id) {
            return sessions.get(id);
        }

        @Override
        public void deleteById(String id) {
            sessions.remove(id);
        }

        @Override
        public Map<String, MapSession> findByIndexNameAndIndexValue(
                String indexName,
                String indexValue) {
            Map<String, MapSession> result = new LinkedHashMap<>();
            sessions.forEach((id, session) -> {
                if (indexValue.equals(session.getAttribute("test-principal"))) {
                    result.put(id, session);
                }
            });
            return result;
        }
    }
}
