package com.aglumova.ws.sensitive;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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

import static org.apache.commons.codec.digest.DigestUtils.md5Hex;
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

  @Test
  public void checkUserPasswordWithMd5Hash_bad_case() {
    final String login = "Test_Pass_Md5";
    final String password = "admin";
    final String insertSql = "INSERT INTO app_user(name, password) VALUES(:name, :password) RETURNING *";
    namedParameterJdbcTemplate
      .query(insertSql, Map.of("name", login, "password", md5Hex(password)), createSingleStringRowMapper());

    final String selectSql = "SELECT password FROM app_user WHERE name = :name";
    final List<String> results = namedParameterJdbcTemplate
      .query(selectSql, Map.of("name", login), (rs, rowNum) -> rs.getString(1));

    assertThat(results).hasSize(1);
    assertThat(results.get(0)).isEqualTo(md5Hex(password));
  }

  @Test
  public void checkUserPasswordWithSha52FixedSaltHash_normal_case() {
    final String login = "Test_Pass_With_Sha512_Fixed_Salt_Enc";
    final String password = "admin";
    final String insertSql = "INSERT INTO app_user(name, password) VALUES(:name, :password) RETURNING *";
    namedParameterJdbcTemplate
      .query(
        insertSql,
        Map.of("name", login, "password", getSHA512SecurePassword(password, "123")),
        createSingleStringRowMapper());

    final String selectSql = "SELECT password FROM app_user WHERE name = :name";
    final List<String> results = namedParameterJdbcTemplate
      .query(selectSql, Map.of("name", login), (rs, rowNum) -> rs.getString(1));

    assertThat(results).hasSize(1);
    assertThat(results.get(0)).isEqualTo(getSHA512SecurePassword(password, "123"));
  }

  @Test
  public void checkUserPasswordWithSeveralHashIteration_good_case() {
    final String login = "Test_Pass_With_Several_Hash_Iteration";
    final String password = "admin";
    final String firstIteration = getSHA512SecurePassword(password, "123");
    final String secondIteration = getSHA512SecurePassword(firstIteration, null);
    final String insertSql = "INSERT INTO app_user(name, password) VALUES(:name, :password) RETURNING *";
    namedParameterJdbcTemplate
      .query(
        insertSql,
        Map.of("name", login, "password", secondIteration),
        createSingleStringRowMapper());

    final String selectSql = "SELECT password FROM app_user WHERE name = :name";
    final List<String> results = namedParameterJdbcTemplate
      .query(selectSql, Map.of("name", login), (rs, rowNum) -> rs.getString(1));

    assertThat(results).hasSize(1);
    assertThat(results.get(0)).isEqualTo(getSHA512SecurePassword(getSHA512SecurePassword(password, "123"), null));
  }

  @Test
  public void checkUserPasswordWithBcryptFixedSaltEncryption_best_case() {
    final String login = "Test_Pass_With_BCrypt_Fixed_Salt_Enc";
    final String password = "admin";
    final String insertSql = "INSERT INTO app_user(name, password) VALUES(:name, :password) RETURNING *";
    namedParameterJdbcTemplate
      .query(
        insertSql, Map.of("name", login, "password", bcryptFixedSaltHash(password)), createSingleStringRowMapper());

    final String selectSql = "SELECT password FROM app_user WHERE name = :name";
    final List<String> results = namedParameterJdbcTemplate
      .query(selectSql, Map.of("name", login), (rs, rowNum) -> rs.getString(1));

    assertThat(results).hasSize(1);
    assertThat(
      BCrypt.verifyer(Version.VERSION_2A)
        .verify(password.getBytes(StandardCharsets.UTF_8), results.get(0).getBytes(StandardCharsets.UTF_8))
        .verified
    ).isTrue();
  }

  @Test
  public void checkUserPasswordWithBcryptDynamicSaltEncryption_best_case() {
    final String login = "Test_Pass_With_Bcrypt_Dynamic_Salt_Enc";
    final String password = "admin";
    final String insertSql = "INSERT INTO app_user(name, password) VALUES(:name, :password) RETURNING *";
    namedParameterJdbcTemplate
      .query(
        insertSql, Map.of("name", login, "password", bcryptDynamicSaltHash(password)), createSingleStringRowMapper());

    final String selectSql = "SELECT password FROM app_user WHERE name = :name";
    final List<String> results = namedParameterJdbcTemplate
      .query(selectSql, Map.of("name", login), (rs, rowNum) -> rs.getString(1));

    assertThat(results).hasSize(1);
    assertThat(
      BCrypt.verifyer(Version.VERSION_2A)
        .verify(password.getBytes(StandardCharsets.UTF_8), results.get(0).getBytes(StandardCharsets.UTF_8))
        .verified
    ).isTrue();
  }

  private String bcryptDynamicSaltHash(final String value) {
    final byte[] hash = BCrypt
      .withDefaults()
      .hash(6, value.getBytes(StandardCharsets.UTF_8));
    return new String(hash, StandardCharsets.UTF_8);
  }

  private String bcryptFixedSaltHash(final String value) {
    final byte[] hash = BCrypt
      .withDefaults()
      .hash(6, "saltsaltsaltsalt".getBytes(StandardCharsets.UTF_8), value.getBytes(StandardCharsets.UTF_8));
    return new String(hash, StandardCharsets.UTF_8);
  }

  private String getSHA512SecurePassword(final String passwordToHash, final String salt) {
    try {
      final MessageDigest md = MessageDigest.getInstance("SHA-512");
      if (salt != null) {
        md.update(salt.getBytes(StandardCharsets.UTF_8));
      }
      final byte[] bytes = md.digest(passwordToHash.getBytes(StandardCharsets.UTF_8));
      final StringBuilder sb = new StringBuilder();
      for (byte aByte : bytes) {
        sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
      }
      return sb.toString();
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private static RowMapper<String> createSingleStringRowMapper() {
    return (rs, rowNum) -> String.format(
      "%s - %s",
      rs.getString(2),
      rs.getString(3));
  }
}
