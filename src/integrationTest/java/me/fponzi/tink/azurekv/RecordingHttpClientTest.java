// Copyright 2026 Federico Ponzi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package me.fponzi.tink.azurekv;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.azure.core.util.Context;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/**
 * Offline unit test for the {@link RecordingHttpClient} VCR mechanics: sequential replay, sanitized
 * matching on method/path/query/body, response synthesis and clear failures on mismatch. This does
 * not need Azure and runs as part of {@code ./gradlew integrationTest}.
 */
public class RecordingHttpClientTest {

  private static final String URL =
      "https://myhsm.managedhsm.azure.net/keys/testkey/testversion/encrypt?api-version=7.5";

  private static final List<RecordingHttpClient.Sanitizer> HOST_SANITIZER =
      Collections.singletonList(
          new RecordingHttpClient.Sanitizer(
              "[A-Za-z0-9-]+\\.managedhsm\\.azure\\.net", "myhsm.managedhsm.azure.net"));

  @Test
  public void replaysChallengeThenSuccessInOrder() {
    List<RecordingHttpClient.Interaction> interactions =
        Arrays.asList(
            new RecordingHttpClient.Interaction(
                "POST", URL, "", 401, Map.of("WWW-Authenticate", "Bearer challenge"), ""),
            new RecordingHttpClient.Interaction(
                "POST",
                URL,
                "{\"alg\":\"A256GCM\",\"value\":\"cGxhaW4\"}",
                200,
                Map.of("Content-Type", "application/json"),
                "{\"value\":\"Y2lwaGVy\"}"));
    RecordingHttpClient client = RecordingHttpClient.forPlayback(interactions, HOST_SANITIZER);

    // First request: the empty-bodied auth probe, sent to the *real* host (sanitized to match).
    HttpResponse challenge =
        client.sendSync(
            new HttpRequest(
                HttpMethod.POST,
                "https://realhsm.managedhsm.azure.net/keys/testkey/testversion/encrypt"
                    + "?api-version=7.5"),
            Context.NONE);
    assertThat(challenge.getStatusCode()).isEqualTo(401);
    assertThat(challenge.getHeaderValue(HttpHeaderName.WWW_AUTHENTICATE))
        .isEqualTo("Bearer challenge");

    // Second request: the authenticated retry carrying the encrypt body.
    HttpRequest retry = new HttpRequest(HttpMethod.POST, URL);
    retry.setBody("{\"alg\":\"A256GCM\",\"value\":\"cGxhaW4\"}");
    HttpResponse success = client.sendSync(retry, Context.NONE);
    assertThat(success.getStatusCode()).isEqualTo(200);
    assertThat(success.getBodyAsString().block()).isEqualTo("{\"value\":\"Y2lwaGVy\"}");
    assertThat(success.getHeaderValue(HttpHeaderName.CONTENT_TYPE)).isEqualTo("application/json");
  }

  @Test
  public void mismatchedRequestBodyFails() {
    List<RecordingHttpClient.Interaction> interactions =
        Collections.singletonList(
            new RecordingHttpClient.Interaction(
                "POST", URL, "{\"alg\":\"A256GCM\"}", 200, Map.of(), "{}"));
    RecordingHttpClient client =
        RecordingHttpClient.forPlayback(interactions, Collections.emptyList());

    HttpRequest wrong = new HttpRequest(HttpMethod.POST, URL);
    wrong.setBody("{\"alg\":\"RSA-OAEP\"}");
    assertThrows(IllegalStateException.class, () -> client.sendSync(wrong, Context.NONE));
  }

  @Test
  public void exhaustedRecordingFails() {
    RecordingHttpClient client =
        RecordingHttpClient.forPlayback(Collections.emptyList(), Collections.emptyList());
    assertThrows(
        IllegalStateException.class,
        () -> client.sendSync(new HttpRequest(HttpMethod.POST, URL), Context.NONE));
  }
}
