package com.aglumova.ws.deserialization.model;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

@AllArgsConstructor
@EqualsAndHashCode
@Getter
@ToString
public class User implements Serializable {

  private final String username;

  private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
    // Read the non-static and non-transient fields of the current class from this stream.
    // This may only be called from the readObject method of the class being deserialized.
    // It will throw the NotActiveException if it is called otherwise.
    in.defaultReadObject();
  }
}
