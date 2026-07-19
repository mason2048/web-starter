package dev.webstarter.core.exception;

import dev.webstarter.core.api.ApiCodes;
import org.springframework.http.HttpStatus;

public class ConflictException extends BusinessException {

    public ConflictException(String message) {
        super(ApiCodes.CONFLICT, HttpStatus.CONFLICT, message);
    }
}
