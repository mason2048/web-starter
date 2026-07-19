package dev.webstarter.core.security;

public abstract class SecuredOperation {

    private final CallerContext callerContext;
    private final PermissionService permissionService;

    protected SecuredOperation(CallerContext callerContext, PermissionService permissionService) {
        this.callerContext = callerContext;
        this.permissionService = permissionService;
    }

    protected CurrentCaller requirePermission(String permission) {
        CurrentCaller caller = callerContext.required();
        permissionService.requirePermission(caller, permission);
        return caller;
    }
}
