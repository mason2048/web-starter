package dev.webstarter.system.web;

import dev.webstarter.system.dto.TraceAuditResponse;
import dev.webstarter.system.service.AuditQueryService;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TraceAuditControllerTest {

    @Test
    void exposesTheExactCorrelatedTraceReturnedByThePermissionCheckedService() throws Exception {
        AuditQueryService service = mock(AuditQueryService.class);
        TraceAuditResponse expected = new TraceAuditResponse(
                "trace-controller-1", List.of(), List.of(), List.of(), false);
        when(service.findByTrace("trace-controller-1")).thenReturn(expected);
        TraceAuditController controller = new TraceAuditController(service);

        assertThat(controller.find("trace-controller-1").data()).isSameAs(expected);
        assertThat(TraceAuditController.class.getAnnotation(RequestMapping.class).value())
                .containsExactly("/api/logs/trace");
        assertThat(TraceAuditController.class.getMethod("find", String.class)
                .getAnnotation(GetMapping.class).value()).containsExactly("/{traceId}");

        verify(service).findByTrace("trace-controller-1");
    }
}
