package dev.webstarter.admin.config;

import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

/** Runs the production safety policy before bean creation, Flyway, or network access. */
public final class ProductionConfigurationInitializer
        implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
        ProductionConfigurationValidator.validate(applicationContext.getEnvironment());
    }
}
