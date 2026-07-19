package dev.webstarter.admin.web;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import dev.webstarter.core.api.ApiCodes;
import dev.webstarter.core.api.ApiResponse;

/** Maps missing MVC/static resources to a stable, non-sensitive API 404 response. */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice
public class WebResourceNotFoundExceptionHandler {

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleNoResourceFound(
            NoResourceFoundException exception) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.error(ApiCodes.NOT_FOUND, "Resource not found"));
    }
}
