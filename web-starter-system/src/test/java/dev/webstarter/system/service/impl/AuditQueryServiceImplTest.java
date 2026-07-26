package dev.webstarter.system.service.impl;

import com.baomidou.mybatisplus.core.conditions.Wrapper;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.MybatisConfiguration;
import com.baomidou.mybatisplus.core.metadata.TableInfoHelper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import dev.webstarter.core.security.CallerContext;
import dev.webstarter.core.security.CallerType;
import dev.webstarter.core.security.CurrentCaller;
import dev.webstarter.core.security.PermissionService;
import dev.webstarter.system.domain.SysLoginLog;
import dev.webstarter.system.domain.SysMcpCallLog;
import dev.webstarter.system.domain.SysOperationLog;
import dev.webstarter.system.persistence.mapper.LoginLogMapper;
import dev.webstarter.system.persistence.mapper.McpCallLogMapper;
import dev.webstarter.system.persistence.mapper.OperationLogMapper;
import dev.webstarter.system.service.SystemPermissions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.apache.ibatis.builder.MapperBuilderAssistant;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuditQueryServiceImplTest {

    private LoginLogMapper loginLogMapper;
    private OperationLogMapper operationLogMapper;
    private McpCallLogMapper mcpCallLogMapper;
    private PermissionService permissionService;
    private AuditQueryServiceImpl service;

    @BeforeEach
    void setUp() {
        initializeTableMetadata(SysLoginLog.class);
        initializeTableMetadata(SysOperationLog.class);
        initializeTableMetadata(SysMcpCallLog.class);
        loginLogMapper = mock(LoginLogMapper.class);
        operationLogMapper = mock(OperationLogMapper.class);
        mcpCallLogMapper = mock(McpCallLogMapper.class);
        permissionService = mock(PermissionService.class);

        CurrentCaller caller = new CurrentCaller(CallerType.USER, "7", "auditor", "Auditor",
                null, null, Set.of(), Set.of(SystemPermissions.AUDIT_LIST), Set.of(), "request-trace");
        CallerContext callerContext = () -> Optional.of(caller);
        service = new AuditQueryServiceImpl(callerContext, permissionService,
                loginLogMapper, operationLogMapper, mcpCallLogMapper);
    }

    @Test
    @SuppressWarnings("unchecked")
    void correlatesAllAuditTypesForOneExactTrace() {
        SysLoginLog login = new SysLoginLog();
        login.setUsername("auditor");
        login.setTraceId("trace-123");
        SysOperationLog operation = new SysOperationLog();
        operation.setActorName("auditor");
        operation.setTraceId("trace-123");
        SysMcpCallLog mcp = new SysMcpCallLog();
        mcp.setActorName("auditor");
        mcp.setToolName("project.list");
        mcp.setTraceId("trace-123");

        when(loginLogMapper.selectList(any(Wrapper.class))).thenReturn(List.of(login));
        when(operationLogMapper.selectList(any(Wrapper.class))).thenReturn(List.of(operation));
        when(mcpCallLogMapper.selectList(any(Wrapper.class))).thenReturn(List.of(mcp));

        var result = service.findByTrace(" trace-123 ");

        assertThat(result.traceId()).isEqualTo("trace-123");
        assertThat(result.loginLogs()).extracting(item -> item.username()).containsExactly("auditor");
        assertThat(result.operationLogs()).extracting(item -> item.actorName()).containsExactly("auditor");
        assertThat(result.mcpCalls()).extracting(item -> item.toolName()).containsExactly("project.list");
        assertThat(result.truncated()).isFalse();
        verify(permissionService).requirePermission(any(CurrentCaller.class),
                org.mockito.ArgumentMatchers.eq(SystemPermissions.AUDIT_LIST));
    }

    @Test
    void rejectsBlankOrOversizedTraceIdentifiersBeforeQuerying() {
        assertThrows(IllegalArgumentException.class, () -> service.findByTrace(" "));
        assertThrows(IllegalArgumentException.class, () -> service.findByTrace("x".repeat(65)));
        assertThrows(IllegalArgumentException.class, () -> service.findByTrace("trace with spaces"));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void appliesSubjectResultTraceResourceToolAndTimeFiltersAtTheDatabaseBoundary() {
        when(loginLogMapper.selectPage(any(Page.class), any(Wrapper.class))).thenReturn(new Page<>());
        when(operationLogMapper.selectPage(any(Page.class), any(Wrapper.class))).thenReturn(new Page<>());
        when(mcpCallLogMapper.selectPage(any(Page.class), any(Wrapper.class))).thenReturn(new Page<>());
        LocalDateTime from = LocalDateTime.of(2026, 7, 19, 10, 0);
        LocalDateTime to = from.plusMinutes(5);

        service.pageLogin(new dev.webstarter.system.service.AuditSearchQuery(
                1, 20, "operator", "SUCCESS", "trace-filter-1",
                null, null, null, null, from, to));
        service.pageOperation(new dev.webstarter.system.service.AuditSearchQuery(
                1, 20, "operator", "SUCCESS", "trace-filter-1",
                "project", "project", "42", null, from, to));
        service.pageMcp(new dev.webstarter.system.service.AuditSearchQuery(
                1, 20, "operator", "SUCCESS", "trace-filter-1",
                null, null, null, "project.create", from, to));

        ArgumentCaptor<Wrapper<SysLoginLog>> loginQuery = ArgumentCaptor.forClass(Wrapper.class);
        ArgumentCaptor<Wrapper<SysOperationLog>> operationQuery = ArgumentCaptor.forClass(Wrapper.class);
        ArgumentCaptor<Wrapper<SysMcpCallLog>> mcpQuery = ArgumentCaptor.forClass(Wrapper.class);
        verify(loginLogMapper).selectPage(any(Page.class), loginQuery.capture());
        verify(operationLogMapper).selectPage(any(Page.class), operationQuery.capture());
        verify(mcpCallLogMapper).selectPage(any(Page.class), mcpQuery.capture());

        assertThat(loginQuery.getValue().getSqlSegment())
                .contains("username", "result", "trace_id", "created_at");
        assertThat(operationQuery.getValue().getSqlSegment())
                .contains("actor_name", "actor_id", "module", "resource_type", "resource_id =",
                        "result", "trace_id", "created_at");
        assertThat(mcpQuery.getValue().getSqlSegment())
                .contains("actor_name", "actor_id", "client_id", "tool_name", "result", "trace_id",
                        "created_at");
        assertThat(((LambdaQueryWrapper<?>) operationQuery.getValue()).getParamNameValuePairs().values())
                .contains("%operator%", "project", "42", "SUCCESS", "trace-filter-1", from, to);
        assertThat(((LambdaQueryWrapper<?>) mcpQuery.getValue()).getParamNameValuePairs().values())
                .contains("%operator%", "project.create", "SUCCESS", "trace-filter-1", from, to);
    }

    @Test
    @SuppressWarnings("unchecked")
    void fetchesOneExtraTraceRowSoExactLimitIsNotReportedAsTruncated() {
        List<SysLoginLog> exactLimit = new ArrayList<>();
        for (int index = 0; index < 200; index++) {
            SysLoginLog item = new SysLoginLog();
            item.setId((long) index + 1);
            item.setTraceId("trace-limit-1");
            exactLimit.add(item);
        }
        when(loginLogMapper.selectList(any(Wrapper.class))).thenReturn(exactLimit);
        when(operationLogMapper.selectList(any(Wrapper.class))).thenReturn(List.of());
        when(mcpCallLogMapper.selectList(any(Wrapper.class))).thenReturn(List.of());

        var exact = service.findByTrace("trace-limit-1");
        assertThat(exact.loginLogs()).hasSize(200);
        assertThat(exact.truncated()).isFalse();

        SysLoginLog overflow = new SysLoginLog();
        overflow.setId(201L);
        overflow.setTraceId("trace-limit-1");
        exactLimit.add(overflow);
        var truncated = service.findByTrace("trace-limit-1");
        assertThat(truncated.loginLogs()).hasSize(200);
        assertThat(truncated.truncated()).isTrue();
    }

    @Test
    @SuppressWarnings("unchecked")
    void redactsArbitraryOperationDetailFromSearchAndTraceResponses() {
        SysOperationLog operation = new SysOperationLog();
        operation.setId(1L);
        operation.setTraceId("trace-redaction-1");
        operation.setDetailJson("{\"password\":\"must-not-leak\"}");
        Page<SysOperationLog> page = new Page<>(1, 20);
        page.setRecords(List.of(operation));
        page.setTotal(1);
        when(operationLogMapper.selectPage(any(Page.class), any(Wrapper.class))).thenReturn(page);
        when(loginLogMapper.selectList(any(Wrapper.class))).thenReturn(List.of());
        when(operationLogMapper.selectList(any(Wrapper.class))).thenReturn(List.of(operation));
        when(mcpCallLogMapper.selectList(any(Wrapper.class))).thenReturn(List.of());

        var query = new dev.webstarter.system.service.AuditSearchQuery(
                1, 20, null, null, "trace-redaction-1",
                null, null, null, null, null, null);
        assertThat(service.pageOperation(query).records().getFirst().detailJson()).isEqualTo("[REDACTED]");
        assertThat(service.findByTrace("trace-redaction-1").operationLogs().getFirst().detailJson())
                .isEqualTo("[REDACTED]");
    }

    private static void initializeTableMetadata(Class<?> entityType) {
        TableInfoHelper.initTableInfo(
                new MapperBuilderAssistant(new MybatisConfiguration(), "test"), entityType);
    }
}
