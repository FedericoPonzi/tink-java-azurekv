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

import com.azure.core.http.HttpClient;
import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.azure.core.util.BinaryData;
import com.azure.core.util.Context;
import com.azure.json.JsonProviders;
import com.azure.json.JsonReader;
import com.azure.json.JsonToken;
import com.azure.json.JsonWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * A minimal, self-contained record/replay {@link HttpClient} (a "VCR") for driving a real {@link
 * com.azure.security.keyvault.keys.cryptography.CryptographyClient} against the Azure Key Vault
 * wire protocol without depending on the live service on every run.
 *
 * <p>This deliberately does <em>not</em> use {@code azure-core-test}'s {@code TestProxyTestBase}:
 * that machinery hardcodes the {@code azure-sdk-for-java} monorepo layout (it resolves recordings
 * relative to an {@code eng/} folder inside a repo named {@code azure-sdk-for-java}) and throws in
 * any other repository.
 *
 * <p><strong>RECORD</strong> delegates each request to a real {@link HttpClient}, materializes the
 * response, applies the configured {@link Sanitizer sanitizers}, and appends the interaction to a
 * list that {@link #persist()} writes to {@code src/integrationTest/resources/session-records/}.
 * The unmodified live response is returned to the caller so the recording run behaves exactly like
 * a normal call.
 *
 * <p><strong>PLAYBACK</strong> serves interactions strictly sequentially. Because the Key Vault SDK
 * pipeline is deterministic, replaying the recorded responses (including the {@code 401} auth
 * challenge) reproduces the exact same request sequence that was recorded. Each incoming request is
 * sanitized the same way and matched against the recorded entry on method, path, query and body, so
 * a regression in the request we build fails the test.
 */
final class RecordingHttpClient implements HttpClient {

  /** A single recorded request/response exchange. */
  static final class Interaction {
    String method;
    String url;
    String requestBody;
    int statusCode;
    Map<String, String> headers;
    String responseBody;

    Interaction() {
      this.headers = new LinkedHashMap<>();
    }

    Interaction(
        String method,
        String url,
        String requestBody,
        int statusCode,
        Map<String, String> headers,
        String responseBody) {
      this.method = method;
      this.url = url;
      this.requestBody = requestBody;
      this.statusCode = statusCode;
      this.headers = new LinkedHashMap<>(headers);
      this.responseBody = responseBody;
    }
  }

  /** A regex-based string redaction applied to URLs, bodies and recorded header values. */
  static final class Sanitizer {
    private final Pattern pattern;
    private final String replacement;

    Sanitizer(String regex, String replacement) {
      this.pattern = Pattern.compile(regex);
      this.replacement = replacement;
    }

    String apply(String input) {
      return input == null ? null : pattern.matcher(input).replaceAll(replacement);
    }
  }

  /** Response headers that are safe and necessary to replay; everything else is dropped. */
  private static final List<String> HEADER_ALLOWLIST = List.of("Content-Type", "WWW-Authenticate");

  private final boolean record;
  private final List<Sanitizer> sanitizers;
  private final List<Interaction> interactions;
  private final HttpClient delegate;
  private final Path recordFile;
  private int cursor;

  private RecordingHttpClient(
      boolean record,
      List<Sanitizer> sanitizers,
      List<Interaction> interactions,
      HttpClient delegate,
      Path recordFile) {
    this.record = record;
    this.sanitizers = List.copyOf(sanitizers);
    this.interactions = interactions;
    this.delegate = delegate;
    this.recordFile = recordFile;
  }

  /** Creates a recording client that captures live traffic to {@code session-records/name.json}. */
  static RecordingHttpClient recording(
      String name, HttpClient delegate, List<Sanitizer> sanitizers) {
    Path file = Paths.get("src/integrationTest/resources/session-records", name + ".json");
    return new RecordingHttpClient(true, sanitizers, new ArrayList<>(), delegate, file);
  }

  /** Creates a playback client backed by the committed recording on the classpath. */
  static RecordingHttpClient playback(String name, List<Sanitizer> sanitizers) {
    try (InputStream in = recordingStream(name)) {
      if (in == null) {
        throw new IllegalStateException("Missing recording session-records/" + name + ".json");
      }
      return new RecordingHttpClient(false, sanitizers, readRecording(in), null, null);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** Creates a playback client from in-memory interactions (used by the VCR's own unit test). */
  static RecordingHttpClient forPlayback(
      List<Interaction> interactions, List<Sanitizer> sanitizers) {
    return new RecordingHttpClient(false, sanitizers, new ArrayList<>(interactions), null, null);
  }

  /** Whether a committed recording exists on the classpath for {@code name}. */
  static boolean hasRecording(String name) {
    try (InputStream in = recordingStream(name)) {
      return in != null;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private static InputStream recordingStream(String name) {
    return RecordingHttpClient.class.getResourceAsStream("/session-records/" + name + ".json");
  }

  @Override
  public Mono<HttpResponse> send(HttpRequest request) {
    return Mono.fromCallable(() -> handle(request));
  }

  @Override
  public HttpResponse sendSync(HttpRequest request, Context context) {
    return handle(request);
  }

  private HttpResponse handle(HttpRequest request) {
    return record ? handleRecord(request) : handlePlayback(request);
  }

  private HttpResponse handleRecord(HttpRequest request) {
    String requestBody = bodyOf(request);
    HttpResponse live = delegate.sendSync(request, Context.NONE);
    byte[] responseBody = live.getBodyAsByteArray().block();
    if (responseBody == null) {
      responseBody = new byte[0];
    }

    Interaction interaction = new Interaction();
    interaction.method = request.getHttpMethod().toString();
    interaction.url = sanitize(request.getUrl().toString());
    interaction.requestBody = sanitize(requestBody);
    interaction.statusCode = live.getStatusCode();
    interaction.headers = allowlistedHeaders(live.getHeaders());
    interaction.responseBody = sanitize(new String(responseBody, StandardCharsets.UTF_8));
    interactions.add(interaction);

    // Hand the caller the genuine, unsanitized response so recording behaves like a real call.
    return new RecordedHttpResponse(request, live.getStatusCode(), live.getHeaders(), responseBody);
  }

  private HttpResponse handlePlayback(HttpRequest request) {
    if (cursor >= interactions.size()) {
      throw new IllegalStateException(
          "No recorded interaction left for unexpected request " + request.getUrl());
    }
    Interaction expected = interactions.get(cursor++);
    String method = request.getHttpMethod().toString();
    String url = sanitize(request.getUrl().toString());
    String body = sanitize(bodyOf(request));

    URI actual = toUri(url);
    URI recorded = toUri(expected.url);
    if (!method.equalsIgnoreCase(expected.method)
        || !Objects.equals(actual.getPath(), recorded.getPath())
        || !Objects.equals(actual.getQuery(), recorded.getQuery())
        || !Objects.equals(body, expected.requestBody)) {
      throw new IllegalStateException(
          "Recorded interaction #"
              + (cursor - 1)
              + " does not match the request.\n  expected: "
              + expected.method
              + " "
              + expected.url
              + "\n           body="
              + expected.requestBody
              + "\n  actual:   "
              + method
              + " "
              + url
              + "\n           body="
              + body);
    }
    return new RecordedHttpResponse(
        request,
        expected.statusCode,
        toHeaders(expected.headers),
        expected.responseBody.getBytes(StandardCharsets.UTF_8));
  }

  /** Writes the captured interactions to the recording file, validating their shape first. */
  void persist() throws IOException {
    validateSequence();
    Files.createDirectories(recordFile.getParent());
    try (OutputStream os = Files.newOutputStream(recordFile)) {
      writeRecording(interactions, os);
    }
  }

  private void validateSequence() {
    if (interactions.isEmpty()) {
      throw new IllegalStateException("Nothing was recorded; expected encrypt + decrypt traffic.");
    }
    for (Interaction it : interactions) {
      String path = toUri(it.url).getPath();
      boolean expectedPath = path.endsWith("/encrypt") || path.endsWith("/decrypt");
      boolean expectedStatus = it.statusCode == 200 || it.statusCode == 401;
      if (!"POST".equalsIgnoreCase(it.method) || !expectedPath || !expectedStatus) {
        throw new IllegalStateException(
            "Unexpected recorded interaction (only POST encrypt/decrypt with 200/401 are"
                + " expected): "
                + it.method
                + " "
                + it.url
                + " -> "
                + it.statusCode
                + ". Review the traffic before committing.");
      }
    }
  }

  private String sanitize(String value) {
    String result = value;
    for (Sanitizer sanitizer : sanitizers) {
      result = sanitizer.apply(result);
    }
    return result;
  }

  private Map<String, String> allowlistedHeaders(HttpHeaders headers) {
    Map<String, String> result = new LinkedHashMap<>();
    for (String name : HEADER_ALLOWLIST) {
      String value = headers.getValue(HttpHeaderName.fromString(name));
      if (value != null) {
        result.put(name, sanitize(value));
      }
    }
    return result;
  }

  private static HttpHeaders toHeaders(Map<String, String> headers) {
    HttpHeaders result = new HttpHeaders();
    headers.forEach((name, value) -> result.set(HttpHeaderName.fromString(name), value));
    return result;
  }

  private static String bodyOf(HttpRequest request) {
    BinaryData body = request.getBodyAsBinaryData();
    return body == null ? "" : body.toString();
  }

  private static URI toUri(String url) {
    try {
      return new URI(url);
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Malformed URL " + url, e);
    }
  }

  private static void writeRecording(List<Interaction> interactions, OutputStream os)
      throws IOException {
    try (JsonWriter writer = JsonProviders.createWriter(os)) {
      writer.writeStartObject();
      writer.writeStartArray("interactions");
      for (Interaction it : interactions) {
        writer.writeStartObject();
        writer.writeStringField("method", it.method);
        writer.writeStringField("url", it.url);
        writer.writeStringField("requestBody", it.requestBody);
        writer.writeIntField("statusCode", it.statusCode);
        writer.writeStartObject("headers");
        for (Map.Entry<String, String> header : it.headers.entrySet()) {
          writer.writeStringField(header.getKey(), header.getValue());
        }
        writer.writeEndObject();
        writer.writeStringField("responseBody", it.responseBody);
        writer.writeEndObject();
      }
      writer.writeEndArray();
      writer.writeEndObject();
      writer.flush();
    }
  }

  private static List<Interaction> readRecording(InputStream in) throws IOException {
    List<Interaction> interactions = new ArrayList<>();
    try (JsonReader reader = JsonProviders.createReader(in)) {
      reader.nextToken(); // START_OBJECT
      while (reader.nextToken() != JsonToken.END_OBJECT) {
        String field = reader.getFieldName();
        reader.nextToken();
        if ("interactions".equals(field)) {
          while (reader.nextToken() != JsonToken.END_ARRAY) {
            interactions.add(readInteraction(reader));
          }
        } else {
          reader.skipChildren();
        }
      }
    }
    return interactions;
  }

  private static Interaction readInteraction(JsonReader reader) throws IOException {
    Interaction it = new Interaction();
    while (reader.nextToken() != JsonToken.END_OBJECT) {
      String field = reader.getFieldName();
      reader.nextToken();
      switch (field) {
        case "method":
          it.method = reader.getString();
          break;
        case "url":
          it.url = reader.getString();
          break;
        case "requestBody":
          it.requestBody = reader.getString();
          break;
        case "statusCode":
          it.statusCode = reader.getInt();
          break;
        case "responseBody":
          it.responseBody = reader.getString();
          break;
        case "headers":
          while (reader.nextToken() != JsonToken.END_OBJECT) {
            String headerName = reader.getFieldName();
            reader.nextToken();
            it.headers.put(headerName, reader.getString());
          }
          break;
        default:
          reader.skipChildren();
          break;
      }
    }
    return it;
  }

  /** An {@link HttpResponse} backed by recorded (or just-captured) bytes. */
  private static final class RecordedHttpResponse extends HttpResponse {
    private final int statusCode;
    private final HttpHeaders headers;
    private final byte[] body;

    RecordedHttpResponse(HttpRequest request, int statusCode, HttpHeaders headers, byte[] body) {
      super(request);
      this.statusCode = statusCode;
      this.headers = headers;
      this.body = body;
    }

    @Override
    public int getStatusCode() {
      return statusCode;
    }

    @Override
    @SuppressWarnings("deprecation") // Mandatory override of a deprecated abstract method.
    public String getHeaderValue(String name) {
      return headers.getValue(HttpHeaderName.fromString(name));
    }

    @Override
    public HttpHeaders getHeaders() {
      return headers;
    }

    @Override
    public Flux<ByteBuffer> getBody() {
      return body.length == 0 ? Flux.empty() : Flux.defer(() -> Flux.just(ByteBuffer.wrap(body)));
    }

    @Override
    public Mono<byte[]> getBodyAsByteArray() {
      return body.length == 0 ? Mono.empty() : Mono.just(body);
    }

    @Override
    public Mono<String> getBodyAsString() {
      return getBodyAsString(StandardCharsets.UTF_8);
    }

    @Override
    public Mono<String> getBodyAsString(java.nio.charset.Charset charset) {
      return body.length == 0 ? Mono.empty() : Mono.just(new String(body, charset));
    }
  }
}
