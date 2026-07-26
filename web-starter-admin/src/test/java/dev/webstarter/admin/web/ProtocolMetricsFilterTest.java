package dev.webstarter.admin.web;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@ExtendWith(OutputCaptureExtension.class)
class ProtocolMetricsFilterTest {

    @Test
    void recordsOAuthAndRateLimitOutcomesUsingOnlyBoundedTags(CapturedOutput output) throws Exception {
        SimpleMeterRegistry metrics = new SimpleMeterRegistry();
        ProtocolMetricsFilter filter = new ProtocolMetricsFilter(metrics);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setStatus(429);
        Logger logger = (Logger) LoggerFactory.getLogger(ProtocolMetricsFilter.class);
        ListAppender<ILoggingEvent> events = new ListAppender<>();
        events.start();
        logger.addAppender(events);

        MDC.put("traceId", "trace-metrics-test");
        try {
            filter.doFilter(request, response, new MockFilterChain());
        }
        finally {
            logger.detachAppender(events);
            events.stop();
            MDC.remove("traceId");
        }

        assertThat(metrics.get("webstarter.protocol.requests")
                .tags("endpoint", "oauth_token", "method", "POST", "outcome", "RATE_LIMITED")
                .counter().count()).isEqualTo(1);
        assertThat(metrics.get("webstarter.rate_limited")
                .tag("endpoint", "oauth_token").counter().count()).isEqualTo(1);
        assertThat(events.list).hasSize(1);
        assertThat(events.list.getFirst().getMDCPropertyMap())
                .containsEntry("traceId", "trace-metrics-test");
        assertThat(events.list.getFirst().getKeyValuePairs())
                .extracting(pair -> pair.key)
                .containsExactly("endpoint", "method", "outcome")
                .doesNotContain("traceId");
        assertThat(output).contains("protocol_request");
    }
}
