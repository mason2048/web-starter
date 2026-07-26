package dev.webstarter.system.domain;

import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.annotation.Version;

@TableName("sys_user")
public class SysUser extends AbstractSystemEntity {

    private String username;
    private String displayName;
    private String passwordHash;
    private String email;
    private String mobile;
    private String status;
    private Long securityEpoch;
    private java.time.LocalDateTime passwordChangedAt;

    @Version
    private Integer version;

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getMobile() { return mobile; }
    public void setMobile(String mobile) { this.mobile = mobile; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public Long getSecurityEpoch() { return securityEpoch; }
    public void setSecurityEpoch(Long securityEpoch) { this.securityEpoch = securityEpoch; }
    public java.time.LocalDateTime getPasswordChangedAt() { return passwordChangedAt; }
    public void setPasswordChangedAt(java.time.LocalDateTime passwordChangedAt) { this.passwordChangedAt = passwordChangedAt; }
    public Integer getVersion() { return version; }
    public void setVersion(Integer version) { this.version = version; }
}
