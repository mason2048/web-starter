package dev.webstarter.mcp.acceptance;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;

/** Post-restart half of the V2-AC-34 graceful-shutdown observation. */
class McpSdkGovernanceShutdownRuntimeIT {

    @Test
    void provesGracefulShutdownRemovedUnexpiredSessionBeforeRestart() throws Exception {
        McpGovernanceRuntimeSupport runtime = new McpGovernanceRuntimeSupport();
        Path credentials = McpGovernanceRuntimeSupport.credentialDirectory();
        var state = McpGovernanceRuntimeSupport.readShutdownState(
                McpGovernanceRuntimeSupport.stateFile());
        assertThat(state.tracePrefix()).isEqualTo(McpGovernanceRuntimeSupport.tracePrefix());

        assertProbeAge(state);

        String currentBearer = McpGovernanceRuntimeSupport.bearer(
                credentials, "delete.json");
        var currentSdkSession = runtime.initializeOfficialSdk(
                currentBearer,
                McpGovernanceRuntimeSupport.trace(state.tracePrefix(), "restart-identity"),
                "web-starter-governance-restart-acceptance");
        assertThat(currentSdkSession.rawSession().id()).isNotEqualTo(state.sessionId());
        assertProbeAge(state);

        String oldBearer = McpGovernanceRuntimeSupport.bearer(credentials, "sdk.json");
        var oldSession = new McpGovernanceRuntimeSupport.RawSession(
                state.sessionId(), oldBearer);
        var rejected = runtime.ping(
                oldSession,
                McpGovernanceRuntimeSupport.trace(state.tracePrefix(), "shutdown-old-session"));
        assertThat(rejected.status()).isEqualTo(404);
        assertThat(McpGovernanceRuntimeSupport.errorCode(rejected))
                .isEqualTo("SESSION_NOT_FOUND");
        assertThat(currentSdkSession.client().closeGracefully()).isTrue();
    }

    private static void assertProbeAge(McpGovernanceRuntimeSupport.ShutdownState state) {
        long ageMillis = System.currentTimeMillis() - state.createdAtEpochMillis();
        assertThat(ageMillis)
                .as("restart probe must run before idle TTL can remove the session")
                .isBetween(1L, (McpGovernanceRuntimeSupport.IDLE_TTL_SECONDS - 5L) * 1_000L);
    }
}
