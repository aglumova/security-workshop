package com.aglumova.ws.authentication;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCrypt.Version;
import com.aglumova.ws.SecurityWsApplication;
import com.aglumova.ws.injection.sql.container.PostgreSqlContainerConfig;
import com.github.database.rider.core.api.configuration.DBUnit;
import com.github.database.rider.core.api.configuration.Orthography;
import com.github.database.rider.spring.api.DBRider;
import lombok.extern.log4j.Log4j2;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest(
  classes = {
    SecurityWsApplication.class
  },
  webEnvironment = WebEnvironment.RANDOM_PORT
)
@ContextConfiguration(
  initializers = PostgreSqlContainerConfig.DbInitializer.class
)
@DBRider
@DBUnit(
  caseInsensitiveStrategy = Orthography.LOWERCASE,
  leakHunter = true
)
@Log4j2
public class PasswordStorageTest {

  @Autowired
  private NamedParameterJdbcTemplate namedParameterJdbcTemplate;

  // The worst case: we store sensitive information without any encryption.
  @Test
  public void checkUserPasswordWithoutEncryption_worst_case() {
    final String login = "Test_Pass_Without_Enc";
    final String password = "admin";
    final String insertSql = "INSERT INTO app_user(name, password) VALUES(:name, :password) RETURNING *";
    namedParameterJdbcTemplate
      .query(insertSql, Map.of("name", login, "password", password), createSingleStringRowMapper());

    final String selectSql = "SELECT password FROM app_user WHERE name = :name";
    final List<String> results = namedParameterJdbcTemplate
      .query(selectSql, Map.of("name", login), (rs, rowNum) -> rs.getString(1));

    assertThat(results).hasSize(1);
    assertThat(results.get(0)).isEqualTo(password);
  }

  // The normal case: We store sensitive information with fixed salt encryption.
  @Test
  public void checkUserPasswordWithFixedSaltEncryption_normal_case() {
    final String login = "Test_Pass_With_Fixed_Salt_Enc";
    final String password = "admin";
    final String insertSql = "INSERT INTO app_user(name, password) VALUES(:name, :password) RETURNING *";
    namedParameterJdbcTemplate
      .query(insertSql, Map.of("name", login, "password", fixedSaltHash(password)), createSingleStringRowMapper());

    final String selectSql = "SELECT password FROM app_user WHERE name = :name";
    final List<String> results = namedParameterJdbcTemplate
      .query(selectSql, Map.of("name", login), (rs, rowNum) -> rs.getString(1));

    assertThat(results).hasSize(1);
    assertThat(results.get(0)).isNotEqualTo(password);
    assertThat(
      BCrypt.verifyer(Version.VERSION_2A)
        .verify(password.getBytes(StandardCharsets.UTF_8), results.get(0).getBytes(StandardCharsets.UTF_8))
        .verified
    ).isTrue();
  }

  // The best case: We store sensitive information with dynamic salt encryption.
  @Test
  public void checkUserPasswordWithDynamicSaltEncryption_best_case() {
    final String login = "Test_Pass_With_Dynamic_Salt_Enc";
    final String password = "admin";
    final String insertSql = "INSERT INTO app_user(name, password) VALUES(:name, :password) RETURNING *";
    namedParameterJdbcTemplate
      .query(insertSql, Map.of("name", login, "password", dynamicSaltHash(password)), createSingleStringRowMapper());

    final String selectSql = "SELECT password FROM app_user WHERE name = :name";
    final List<String> results = namedParameterJdbcTemplate
      .query(selectSql, Map.of("name", login), (rs, rowNum) -> rs.getString(1));

    assertThat(results).hasSize(1);
    assertThat(results.get(0)).isNotEqualTo(password);
    assertThat(results.get(0)).isNotEqualTo(password);
    assertThat(
      BCrypt.verifyer(Version.VERSION_2A)
        .verify(password.getBytes(StandardCharsets.UTF_8), results.get(0).getBytes(StandardCharsets.UTF_8))
        .verified
    ).isTrue();
  }

  private String dynamicSaltHash(final String value) {
    final byte[] hash = BCrypt
      .withDefaults()
      .hash(6, value.getBytes(StandardCharsets.UTF_8));
    return new String(hash, StandardCharsets.UTF_8);
  }

  private String fixedSaltHash(final String value) {
    final byte[] hash = BCrypt
      .withDefaults()
      .hash(6, "saltsaltsaltsalt".getBytes(StandardCharsets.UTF_8), value.getBytes(StandardCharsets.UTF_8));
    return new String(hash, StandardCharsets.UTF_8);
  }

  private static RowMapper<String> createSingleStringRowMapper() {
    return (rs, rowNum) -> String.format(
      "%s - %s",
      rs.getString(2),
      rs.getString(3));
  }
}
