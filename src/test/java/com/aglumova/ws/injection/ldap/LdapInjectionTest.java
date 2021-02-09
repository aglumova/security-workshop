package com.aglumova.ws.injection.ldap;

import java.util.List;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;

import com.aglumova.ws.SecurityWsApplication;
import com.aglumova.ws.injection.ldap.data.Person;
import lombok.extern.log4j.Log4j2;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.ldap.query.LdapQueryBuilder.query;

@RunWith(SpringRunner.class)
@ActiveProfiles("ldap")
@SpringBootTest(
  classes = {
    SecurityWsApplication.class
  },
  webEnvironment = WebEnvironment.RANDOM_PORT
)
@Log4j2
public class LdapInjectionTest {

  @Autowired
  private LdapTemplate ldapTemplate;

  @Test
  public void findPersonWitPotentialInjection() {
    final String value = "*";
    final List<Person> persons = ldapTemplate.search(
      "",
      "(&(objectclass=person)(cn=" + value + "))",
      new PersonAttributesMapper());

    assertThat(persons).isNotEmpty();
    assertThat(persons).hasSizeGreaterThan(1);
  }

  @Test
  public void findPersonWitPotentialInjectionDoesNotReturnAnyWithCustomFilter() {
    final String value = "*";
    final List<Person> persons = ldapTemplate.search(
      "",
      "(&(objectclass=person)(cn=" + escapeLDAPSearchFilter(value) + "))",
      new PersonAttributesMapper());

    assertThat(persons).isEmpty();
  }

  @Test
  public void findPersonWitPotentialInjectionDoesNotReturnAnyWithFrameworkFilter() {
    final String value = "*";
    final List<Person> persons = ldapTemplate.search(
      query().where("objectclass").is("person").and("cn").is(value),
      new PersonAttributesMapper());

    assertThat(persons).isEmpty();
  }

  private static class PersonAttributesMapper implements AttributesMapper<Person> {

    public Person mapFromAttributes(Attributes attrs) throws NamingException {
      Person person = new Person();
      person.setFullName((String) attrs.get("cn").get());
      person.setLastName((String) attrs.get("sn").get());
      return person;
    }
  }

  private String escapeLDAPSearchFilter(final String filter) {
    final StringBuilder sb = new StringBuilder();

    for (int i = 0; i < filter.length(); i++) {
      final char curChar = filter.charAt(i);
      switch (curChar) {
        case '\\':
          sb.append("\\5c");
          break;
        case '*':
          sb.append("\\2a");
          break;
        case '(':
          sb.append("\\28");
          break;
        case ')':
          sb.append("\\29");
          break;
        case '\u0000':
          sb.append("\\00");
          break;
        default:
          sb.append(curChar);
      }
    }
    return sb.toString();
  }
}

