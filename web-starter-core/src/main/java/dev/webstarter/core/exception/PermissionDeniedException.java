package dev.webstarter.core.exception;

import dev.webstarter.core.api.ApiCodes;
import org.springframework.http.HttpStatus;

public class PermissionDeniedException extends BusinessException {

    public PermissionDeniedException(String permission) {
        super(ApiCodes.FORBIDDEN, HttpStatus.FORBIDDEN, "Missing permission: " + permission);
    }
}
