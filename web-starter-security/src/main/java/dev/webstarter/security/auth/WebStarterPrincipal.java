package dev.webstarter.security.auth;

import java.security.Principal;

import dev.webstarter.core.security.CurrentCaller;

public record WebStarterPrincipal(CurrentCaller caller, long securityEpoch)
        implements Principal, CallerPrincipal {

    public WebStarterPrincipal(CurrentCaller caller) {
        this(caller, 0);
    }

    @Override
    public String getName() {
        return caller.username();
    }
}
