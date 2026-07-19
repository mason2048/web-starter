package dev.webstarter.core.exception;

import dev.webstarter.core.api.ApiCodes;
import org.springframework.http.HttpStatus;

public class AuthenticationRequiredException extends BusinessException {

    public AuthenticationRequiredException() {
        super(ApiCodes.UNAUTHORIZED, HttpStatus.UNAUTHORIZED, "Authentication is required");
    }
}
