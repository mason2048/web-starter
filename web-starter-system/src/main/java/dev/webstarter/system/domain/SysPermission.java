package dev.webstarter.system.domain;

import com.baomidou.mybatisplus.annotation.TableName;

@TableName("sys_permission")
public class SysPermission extends AbstractSystemEntity {

    private String code;
    private String name;
    private String type;
    private String description;
    private String status;

    public String getCode() { return code; }
    public void setCode(String code) { this.code = code; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}
