package com.aglumova.ws.authentication;

import java.util.List;
import java.util.UUID;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
public class PredictableSessionIdTest {

  @Test
  public void predictableSessionId() {
    final List<Integer> activeSessionsIds = List.of(1, 100, 4, 10, 8, 9, 11, 29, 19, 18, 99, 78, 2);

    int potentialStolenSessionsCount = 0;
    for (int i = 0; i < 100; i++) {
      potentialStolenSessionsCount += activeSessionsIds.contains(i) ? 1 : 0;
    }

    assertThat(potentialStolenSessionsCount).isGreaterThan(0);
  }

  @Test
  public void nonPredictableSessionId() {
    final List<UUID> activeSessionsIds =
      List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());

    int potentialStolenSessionsCount = 0;
    for (int i = 0; i < 10; i++) {
      potentialStolenSessionsCount += activeSessionsIds.contains(UUID.randomUUID()) ? 1 : 0;
    }

    // NOTE: Such mechanism is not 100% unpredictable.
    assertThat(potentialStolenSessionsCount).isEqualTo(0);
  }
}
