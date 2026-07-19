package dev.webstarter.system.dto;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

class RoleCreateRequestValidationTest {

    @Test
    void acceptsTheUppercaseRoleCodesUsedByTheAcceptanceContract() {
        assertThat(codePattern().matcher("PROJECT_VIEWER").matches()).isTrue();
    }

    @Test
    void rejectsLowercaseRoleCodesSoStoredCodesStayCanonical() {
        assertThat(codePattern().matcher("project_viewer").matches()).isFalse();
    }

    private static Pattern codePattern() {
        try {
            var constraint = RoleCreateRequest.class.getDeclaredMethod("code")
                    .getAnnotation(jakarta.validation.constraints.Pattern.class);
            return Pattern.compile(constraint.regexp());
        } catch (NoSuchMethodException exception) {
            throw new AssertionError(exception);
        }
    }
}
