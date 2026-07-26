package dev.webstarter.system.audit;

import java.util.regex.Pattern;

/** Fixed REST write boundary and its canonical audit resource identity. */
public record OperationAuditRoute(
        String pathPrefix,
        String module,
        String resourceType,
        boolean successAuditedByService) {

    private static final int MAX_PATH_PREFIX_LENGTH = 133;
    private static final int MAX_NAME_LENGTH = 64;
    private static final Pattern PATH = Pattern.compile(
            "/api/[a-z0-9]+(?:-[a-z0-9]+)*(?:/[a-z0-9]+(?:-[a-z0-9]+)*)*");
    private static final Pattern NAME = Pattern.compile("[a-z][a-z0-9]*(?:-[a-z0-9]+)*");

    public OperationAuditRoute {
        if (pathPrefix == null
                || pathPrefix.length() > MAX_PATH_PREFIX_LENGTH
                || !PATH.matcher(pathPrefix).matches()
                || pathPrefix.contains("..")) {
            throw new IllegalArgumentException("operation audit path prefix must be a normalized /api path");
        }
        if (module == null
                || module.length() > MAX_NAME_LENGTH
                || !NAME.matcher(module).matches()) {
            throw new IllegalArgumentException("operation audit module must be lower kebab case");
        }
        if (resourceType == null
                || resourceType.length() > MAX_NAME_LENGTH
                || !NAME.matcher(resourceType).matches()) {
            throw new IllegalArgumentException("operation audit resource type must be lower kebab case");
        }
    }

    public static OperationAuditRoute serviceOwned(
            String pathPrefix,
            String module,
            String resourceType) {
        return new OperationAuditRoute(pathPrefix, module, resourceType, true);
    }

    public static OperationAuditRoute filterOwned(
            String pathPrefix,
            String module,
            String resourceType) {
        return new OperationAuditRoute(pathPrefix, module, resourceType, false);
    }

    public boolean matches(String requestPath) {
        return requestPath != null
                && (requestPath.equals(pathPrefix) || requestPath.startsWith(pathPrefix + "/"));
    }
}
