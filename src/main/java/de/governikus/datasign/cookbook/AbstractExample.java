package de.governikus.datasign.cookbook;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import eu.europa.esig.dss.model.DSSDocument;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Properties;

class AbstractExample {

    protected final Properties props = new Properties();

    private final HttpClient httpClient = HttpClient.newBuilder().build();

    protected HttpRequest.Builder GET(String restPath) {
        return HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(props.getProperty("url")).resolve(restPath));
    }

    protected HttpRequest.Builder POST(String restPath, byte[] body) {
        return HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .uri(URI.create(props.getProperty("url")).resolve(restPath))
                .header("Content-Type", "application/octet-stream");
    }

    protected HttpRequest.Builder POST(String restPath, Object body) throws Exception {
        return HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(toJsonString(body)))
                .uri(URI.create(props.getProperty("url")).resolve(restPath))
                .header("Content-Type", "application/json");
    }

    protected HttpRequest.Builder PUT(String restPath, Object body) throws Exception {
        return HttpRequest.newBuilder()
                .PUT(HttpRequest.BodyPublishers.ofString(toJsonString(body)))
                .uri(URI.create(props.getProperty("url")).resolve(restPath))
                .header("Content-Type", "application/json");
    }

    protected void send(HttpRequest.Builder request) throws Exception {
        responseFrom(request);
    }

    protected <T> T send(HttpRequest.Builder request, Class<T> responseType) throws Exception {
        var httpResponse = responseFrom(request);
        return fromJson(httpResponse, responseType);
    }

    protected byte[] retrieveBytes(HttpRequest.Builder request) throws Exception {
        return binaryResponseFrom(request).body();
    }

    private HttpResponse<String> responseFrom(HttpRequest.Builder httpRequest) throws Exception {

        var httpResponse = httpClient.send(httpRequest.build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

        if (httpResponse.statusCode() >= 400) {
            throw new RuntimeException();
        }

        return httpResponse;
    }

    private HttpResponse<byte[]> binaryResponseFrom(HttpRequest.Builder httpRequest) throws IOException, InterruptedException {

        var httpResponse = httpClient.send(httpRequest.build(),
                HttpResponse.BodyHandlers.ofByteArray());

        if (httpResponse.statusCode() >= 400) {
            throw new RuntimeException();
        }

        return httpResponse;
    }

    protected String toJsonString(Object request) throws Exception {
        return createObjectMapper().writeValueAsString(request);
    }

    protected <T> T fromJson(HttpResponse<String> httpResponse, Class<T> responseType) throws Exception {
        return createObjectMapper().readValue(httpResponse.body(), responseType);
    }

    private static ObjectMapper createObjectMapper() {
        var om = new ObjectMapper();
        om.registerModule(new JavaTimeModule());
        return om;
    }

    protected static void writeToDisk(DSSDocument bytes, String filename) throws Exception {
        var out = new FileOutputStream(filename);
        out.write(bytes.openStream().readAllBytes());
        out.close();
    }

    protected static X509Certificate toX509Certificate(byte[] certificate) throws Exception {
        var factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificate));
    }

}