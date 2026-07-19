package dev.webstarter.system.domain;

import com.baomidou.mybatisplus.annotation.TableName;

@TableName("sys_login_log")
public class SysLoginLog extends AbstractSystemEntity {

    private String username;
    private String result;
    private String failureReason;
    private String ipAddress;
    private String userAgent;
    private String traceId;

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getResult() { return result; }
    public void setResult(String result) { this.result = result; }
    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String failureReason) { this.failureReason = failureReason; }
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
    public String getTraceId() { return traceId; }
    public void setTraceId(String traceId) { this.traceId = traceId; }
}
