package dev.webstarter.core.exception;

import dev.webstarter.core.api.ApiCodes;
import org.springframework.http.HttpStatus;

public class NotFoundException extends BusinessException {

    public NotFoundException(String message) {
        super(ApiCodes.NOT_FOUND, HttpStatus.NOT_FOUND, message);
    }
}
