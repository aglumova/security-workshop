package com.aglumova.ws.deserialization;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import com.aglumova.ws.deserialization.model.User;
import com.aglumova.ws.deserialization.safe.LookAheadObjectInputStream;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.io.FileUtils;
import org.hamcrest.CoreMatchers;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import ysoserial.payloads.CommonsCollections4;
import ysoserial.payloads.ObjectPayload;

import static org.assertj.core.api.Assertions.assertThat;

@Log4j2
public class DeserializationTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  private final static String serializedFile = "serialized.bin";

  @Test
  public void unsafeDeserializationWithValidObject() {
    //serialize an user object
    final User serialized = new User("Whitepapers");
    serialize(serialized);

    //and this triggers the vulnerability
    final User deserialized = (User) deserialize();

    assertThat(serialized).isEqualTo(deserialized);
  }

  @Test(expected = RuntimeException.class)
  public void unsafeDeserializationWithHarmfulObject() throws Exception {
    //serialize an user object
    final User serialized = new User("Whitepapers");
    serialize(serialized);

    //create a malicious payload. The application will read it thinking it is secure
    final ObjectPayload op = new CommonsCollections4();
    final Object payload = op.getObject("open -na Calculator");
    serialize(payload);

    //and this triggers the vulnerability
    deserialize();
  }

  @Test
  public void safeDeserializationWithHarmfulObject() throws Exception {
    thrown.expect(RuntimeException.class);
    thrown.expect(CoreMatchers.not(CoreMatchers.instanceOf(InvalidClassException.class)));
    thrown.expectMessage("Unauthorized deserialization attempt");

    //serialize an user object
    final User serialized = new User("Whitepapers");
    serialize(serialized);

    //create a malicious payload. The application will read it thinking it is secure
    final ObjectPayload op = new CommonsCollections4();
    final Object payload = op.getObject("open -na Calculator");
    serialize(payload);

    //and this triggers the vulnerability
    safeDeserialize();
  }

  private static Object safeDeserialize() {
    try (final ObjectInputStream in = new LookAheadObjectInputStream(new FileInputStream(serializedFile))) {
      return in.readObject();
    } catch (final IOException | ClassNotFoundException ex) {
      throw new RuntimeException(ex);
    } finally {
      final File fileToDelete = FileUtils.getFile(serializedFile);
      FileUtils.deleteQuietly(fileToDelete);
    }
  }

  private static Object deserialize() {
    try (final ObjectInputStream in = new ObjectInputStream(new FileInputStream(serializedFile))) {
      return in.readObject();
    } catch (final IOException | ClassNotFoundException ex) {
      throw new RuntimeException(ex);
    } finally {
      final File fileToDelete = FileUtils.getFile(serializedFile);
      FileUtils.deleteQuietly(fileToDelete);
    }
  }

  private static void serialize(final Object o) {
    try (final ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(serializedFile))) {
      out.writeObject(o);
    } catch (final IOException ex) {
      throw new RuntimeException(ex);
    }
  }
}
