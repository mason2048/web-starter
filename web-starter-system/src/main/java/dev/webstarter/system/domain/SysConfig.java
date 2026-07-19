package dev.webstarter.system.domain;

import com.baomidou.mybatisplus.annotation.TableName;

@TableName("sys_config")
public class SysConfig extends AbstractSystemEntity {

    private String configKey;
    private String configValue;
    private String valueType;
    private String description;
    private Boolean builtin;

    public String getConfigKey() { return configKey; }
    public void setConfigKey(String configKey) { this.configKey = configKey; }
    public String getConfigValue() { return configValue; }
    public void setConfigValue(String configValue) { this.configValue = configValue; }
    public String getValueType() { return valueType; }
    public void setValueType(String valueType) { this.valueType = valueType; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public Boolean getBuiltin() { return builtin; }
    public void setBuiltin(Boolean builtin) { this.builtin = builtin; }
}
