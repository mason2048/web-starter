package dev.webstarter.admin;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import dev.webstarter.admin.config.ProductionConfigurationInitializer;

@SpringBootApplication(scanBasePackages = "dev.webstarter")
@MapperScan({
        "dev.webstarter.system.persistence.mapper",
        "dev.webstarter.project.persistence.mapper",
        "dev.webstarter.security.persistence.mapper"
})
public class WebStarterApplication {

    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(WebStarterApplication.class);
        application.addInitializers(new ProductionConfigurationInitializer());
        application.run(args);
    }
}
