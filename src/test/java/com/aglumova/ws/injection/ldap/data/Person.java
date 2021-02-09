package com.aglumova.ws.injection.ldap.data;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@EqualsAndHashCode
@Getter
@Setter
@ToString
public class Person {

  private String fullName;
  private String lastName;
}
