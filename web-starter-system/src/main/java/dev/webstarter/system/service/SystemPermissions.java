package dev.webstarter.system.service;

public final class SystemPermissions {

    public static final String USER_LIST = "system:user:list";
    public static final String USER_CREATE = "system:user:create";
    public static final String USER_UPDATE = "system:user:update";
    public static final String USER_REMOVE = "system:user:remove";
    public static final String ROLE_LIST = "system:role:list";
    public static final String ROLE_CREATE = "system:role:create";
    public static final String ROLE_UPDATE = "system:role:update";
    public static final String ROLE_REMOVE = "system:role:remove";
    public static final String PERMISSION_LIST = "system:permission:list";
    public static final String PERMISSION_MANAGE = "system:permission:manage";
    public static final String MENU_LIST = "system:menu:list";
    public static final String MENU_MANAGE = "system:menu:manage";
    public static final String CONFIG_LIST = "system:config:list";
    public static final String CONFIG_MANAGE = "system:config:manage";
    public static final String AUDIT_LIST = "audit:list";

    private SystemPermissions() {
    }
}
