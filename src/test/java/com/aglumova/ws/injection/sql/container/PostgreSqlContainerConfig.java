package com.aglumova.ws.injection.sql.container;

import javax.validation.constraints.NotNull;

import com.aglumova.ws.injection.sql.container.PostgreSqlContainerConfig.DbInitializer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.utility.MountableFile;

@Slf4j
@ContextConfiguration(initializers = {DbInitializer.class})
public final class PostgreSqlContainerConfig {

  private PostgreSqlContainerConfig() {
  }

  public static PostgreSQLContainer postgres =
    (PostgreSQLContainer) new PostgreSQLContainer("postgres:12-alpine")
      .withExposedPorts(8432)
      .withCopyFileToContainer(
        MountableFile.forClasspathResource("db/init_database.sql"),
        "/docker-entrypoint-initdb.d/"
      )
      .withLogConsumer(new Slf4jLogConsumer(log));

  static {
    postgres.start();
  }

  static String getBaseDatasourceUrl() {
    return "jdbc:postgresql://" + postgres.getContainerIpAddress() + ":" + postgres
      .getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT);
  }

  public static class DbInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    @Override
    public void initialize(@NotNull final ConfigurableApplicationContext configurableApplicationContext) {
      TestPropertyValues
        .of(
          "spring.datasource.url=" + getBaseDatasourceUrl() + "/ws",
          "spring.datasource.username=" + postgres.getUsername(),
          "spring.datasource.password=" + postgres.getPassword()
        )
        .applyTo(configurableApplicationContext.getEnvironment());
    }
  }
}
