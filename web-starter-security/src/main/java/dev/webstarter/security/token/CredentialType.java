package dev.webstarter.security.token;

public enum CredentialType {
    PERSONAL_ACCESS_TOKEN("wst_pat_"),
    SERVICE_ACCOUNT_TOKEN("wst_svc_");

    private final String prefix;

    CredentialType(String prefix) {
        this.prefix = prefix;
    }

    public String prefix() {
        return prefix;
    }

    public static CredentialType fromRawToken(String token) {
        for (CredentialType value : values()) {
            if (token != null && token.startsWith(value.prefix)) {
                return value;
            }
        }
        throw new IllegalArgumentException("Unsupported internal credential type");
    }
}
