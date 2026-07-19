package dev.webstarter.core.api;

import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ApiResponseTest {

    @Test
    void successCarriesDataAndTraceId() {
        MDC.clear();

        ApiResponse<String> response = ApiResponse.success("ready");

        assertEquals(ApiCodes.SUCCESS, response.code());
        assertEquals("ready", response.data());
        assertNotNull(response.traceId());
    }
}
