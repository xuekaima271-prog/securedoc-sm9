package com.securedoc.kgc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;

import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/** Documents the fail-closed production placeholders and opt-in-only dev H2 console. */
class ProductionConfigurationTest {

    @Test
    void productionSecretsHaveNoWeakFallbacks() {
        Properties p = yaml("application-prod.yml");

        assertThat(p.getProperty("spring.datasource.username")).isEqualTo("${DB_USER}");
        assertThat(p.getProperty("spring.datasource.password")).isEqualTo("${DB_PASSWORD}");
        assertThat(p.getProperty("kgc.service-token")).isEqualTo("${KGC_SERVICE_TOKEN}");
        assertThat(p.getProperty("kgc.master-key.passphrase")).isEqualTo("${KGC_MASTER_PASSPHRASE}");
    }

    @Test
    void devH2ConsoleRequiresExplicitOptIn() {
        Properties p = yaml("application-dev.yml");

        assertThat(p.getProperty("spring.h2.console.enabled"))
                .isEqualTo("${SECUREDOC_H2_CONSOLE_ENABLED:false}");
    }

    private static Properties yaml(String resource) {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(new ClassPathResource(resource));
        factory.afterPropertiesSet();
        return factory.getObject();
    }
}
