package dev.webstarter.admin.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.session.data.redis.autoconfigure.SessionDataRedisProperties;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

class ApplicationConfigurationTest {

    @Test
    void usesTheSpringBoot4RedisSessionNamespace() throws IOException {
        StandardEnvironment environment = new StandardEnvironment();
        List<PropertySource<?>> sources = new YamlPropertySourceLoader()
                .load("application", new ClassPathResource("application.yml"));
        for (PropertySource<?> source : sources) {
            environment.getPropertySources().addLast(source);
        }

        SessionDataRedisProperties properties = Binder.get(environment)
                .bind("spring.session.data.redis", SessionDataRedisProperties.class)
                .orElseThrow(() -> new AssertionError("Redis session properties are not bound"));

        assertThat(properties.getNamespace()).isEqualTo("web-starter:session");
        assertThat(properties.getFlushMode().name()).isEqualTo("ON_SAVE");
    }
}
