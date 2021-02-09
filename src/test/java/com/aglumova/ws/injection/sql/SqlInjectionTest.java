package com.aglumova.ws.injection.sql;

import java.util.List;
import java.util.Map;

import com.aglumova.ws.SecurityWsApplication;
import com.aglumova.ws.injection.sql.container.PostgreSqlContainerConfig;
import com.github.database.rider.core.api.configuration.DBUnit;
import com.github.database.rider.core.api.configuration.Orthography;
import com.github.database.rider.core.api.dataset.DataSet;
import com.github.database.rider.spring.api.DBRider;
import lombok.extern.log4j.Log4j2;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

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
public class SqlInjectionTest {

  @Autowired
  private JdbcTemplate jdbcTemplate; // allow sql injection Statement

  @Autowired
  private NamedParameterJdbcTemplate namedParameterJdbcTemplate; // prevent sql injection (Prepared Statement)

  @Test
  @DataSet(value = "db/test_data.json", cleanAfter = true)
  public void selectQuery() {
    final String sql = "select id, name, password from app_user";
    final List<String> results = jdbcTemplate.query(sql, createSingleStringRowMapper());

    assertThat(results).isNotEmpty();

    results.forEach(log::debug);
  }

  @Test
  @DataSet(value = "db/test_data.json", cleanAfter = true)
  public void selectQueryWithRestriction() {
    final String param = "Donald";
    final String sql = "select id, name, password from app_user where name = '" + param + "'";
    final List<String> results = jdbcTemplate.query(sql, createSingleStringRowMapper());

    assertThat(results).hasSize(1);

    results.forEach(log::debug);
  }

  @Test(expected = BadSqlGrammarException.class)
  @DataSet(value = "db/test_data.json", cleanAfter = true)
  public void selectQueryWithRestrictionFailingBecauseNotSanitized() {
    final String param = "Dona'ld";
    final String sql = "select id, name, password from app_user where name = '" + param + "'";

    jdbcTemplate.query(sql, createSingleStringRowMapper());

    fail("Should have failed");
  }

  @Test
  @DataSet(value = "db/test_data.json", cleanAfter = true)
  public void selectQueryWithRestrictionHackedBySqlInjection() {
    final String param = "xxx' or '1'='1";
    final String sql = "select id, name, password from app_user where name = '" + param + "'";
    final List<String> results = jdbcTemplate.query(sql, createSingleStringRowMapper());

    assertThat(results.size()).isGreaterThanOrEqualTo(4);

    results.forEach(log::debug);
  }

  @Test
  @DataSet(value = "db/test_data.json", cleanAfter = true)
  public void selectQueryWithRestrictionUsingPreparedStatement() {
    final String param = "Donald";
    final String sql = "select id, name, password from app_user where name = :name";
    final List<String> results = namedParameterJdbcTemplate.query(sql, Map.of("name", param), createSingleStringRowMapper());

    assertThat(results).hasSize(1);

    results.forEach(log::debug);
  }

  @Test
  @DataSet(value = "db/test_data.json", cleanAfter = true)
  public void selectQueryWithRestrictionUsingPreparedStatementSanitized() {
    final String param = "Dona'ld"; // transformed to "Dona''ld"
    final String sql = "select id, name, password from app_user where name = :name";
    final List<String> results = namedParameterJdbcTemplate.query(sql, Map.of("name", param), createSingleStringRowMapper());

    assertThat(results).hasSize(1);
    assertThat(results.get(0)).startsWith("5 - Dona'ld -");

    results.forEach(log::debug);
  }

  @Test
  @DataSet(value = "db/test_data.json", cleanAfter = true)
  public void selectQuerySpringWithRestrictionUsingPreparedStatementTryingSqlInjection() {
    final String param = "xxx' or '1'='1";
    final String sql = "select id, name, password from app_user where name = :name";
    final List<String> results = namedParameterJdbcTemplate.query(sql, Map.of("name", param), createSingleStringRowMapper());

    assertThat(results).isEmpty();
  }

  private static RowMapper<String> createSingleStringRowMapper() {
    return (rs, rowNum) -> String.format(
      "%d - %s - %s",
      rs.getInt(1),
      rs.getString(2),
      rs.getString(3));
  }
}
