package com.aglumova.ws.deserialization.safe;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.List;

import com.aglumova.ws.deserialization.model.User;

public class LookAheadObjectInputStream extends ObjectInputStream {

  private final List<String> allowedTypes;

  public LookAheadObjectInputStream(final InputStream inputStream) throws IOException {
    super(inputStream);
    allowedTypes = List.of(User.class.getName());
  }

  @Override
  protected Class<?> resolveClass(final ObjectStreamClass desc) throws IOException, ClassNotFoundException {
    if (!allowedTypes.contains(desc.getName())) {
      throw new InvalidClassException("Unauthorized deserialization attempt", desc.getName());
    }

    return super.resolveClass(desc);
  }
}
