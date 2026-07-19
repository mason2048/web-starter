package dev.webstarter.admin.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.json.JsonMapper;

class WebIdJsonConfigurationTest {

    private static final long UNSAFE_JAVASCRIPT_INTEGER = 9_007_199_254_740_993L;

    @Test
    void serializesOnlySemanticLongIdentifiersAsDecimalStrings() throws Exception {
        JsonMapper mapper = mapper();

        String json = mapper.writeValueAsString(new IdentifierContract(
                UNSAFE_JAVASCRIPT_INTEGER,
                UNSAFE_JAVASCRIPT_INTEGER + 1,
                List.of(UNSAFE_JAVASCRIPT_INTEGER, Long.MAX_VALUE),
                42L,
                3L,
                20L,
                187L));

        assertThat(json).isEqualTo("{\"id\":\"9007199254740993\","
                + "\"ownerId\":\"9007199254740994\","
                + "\"roleIds\":[\"9007199254740993\",\"9223372036854775807\"],"
                + "\"total\":42,\"page\":3,\"size\":20,\"durationMs\":187}");
    }

    @Test
    void stillAcceptsDecimalStringIdentifiersInRequests() throws Exception {
        JsonMapper mapper = mapper();

        IdentifierRequest request = mapper.readValue(
                "{\"id\":\"9007199254740993\",\"roleIds\":[\"9007199254740994\"]}",
                IdentifierRequest.class);

        assertThat(request.id()).isEqualTo(UNSAFE_JAVASCRIPT_INTEGER);
        assertThat(request.roleIds()).containsExactly(UNSAFE_JAVASCRIPT_INTEGER + 1);
    }

    private static JsonMapper mapper() {
        JsonMapper.Builder builder = JsonMapper.builder();
        new WebIdJsonConfiguration().webIdJsonMapperBuilderCustomizer().customize(builder);
        return builder.build();
    }

    private record IdentifierContract(
            Long id,
            Long ownerId,
            List<Long> roleIds,
            Long total,
            long page,
            long size,
            Long durationMs) {
    }

    private record IdentifierRequest(Long id, List<Long> roleIds) {
    }
}
