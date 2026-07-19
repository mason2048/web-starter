package dev.webstarter.admin.web;

import java.lang.reflect.Method;

import dev.webstarter.core.api.ApiResponse;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

@ControllerAdvice
public class OperationAuditResponseAdvice implements ResponseBodyAdvice<Object> {

    @Override
    public boolean supports(
            MethodParameter returnType,
            Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }

    @Override
    public Object beforeBodyWrite(
            Object body,
            MethodParameter returnType,
            MediaType selectedContentType,
            Class<? extends HttpMessageConverter<?>> selectedConverterType,
            ServerHttpRequest request,
            ServerHttpResponse response) {
        if (body instanceof ApiResponse<?> apiResponse
                && request instanceof ServletServerHttpRequest servletRequest) {
            Object id = extractId(apiResponse.data());
            if (id != null) {
                servletRequest.getServletRequest().setAttribute(
                        OperationAuditRequestContext.RESOURCE_ID_ATTRIBUTE, id.toString());
            }
        }
        return body;
    }

    private static Object extractId(Object value) {
        Object direct = accessor(value, "id");
        if (direct != null) {
            return direct;
        }
        Object nestedClient = accessor(value, "client");
        return accessor(nestedClient, "id");
    }

    private static Object accessor(Object target, String name) {
        if (target == null) {
            return null;
        }
        try {
            Method method = target.getClass().getMethod(name);
            return method.invoke(target);
        }
        catch (ReflectiveOperationException ignored) {
            return null;
        }
    }
}
