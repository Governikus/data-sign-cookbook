package de.governikus.datasign.cookbook.jades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.HashAlgorithm;
import de.governikus.datasign.cookbook.types.SignProvider;
import de.governikus.datasign.cookbook.types.SignatureFormat;
import de.governikus.datasign.cookbook.types.SignatureLevel;
import de.governikus.datasign.cookbook.types.SignatureNiveau;
import de.governikus.datasign.cookbook.types.SignaturePackaging;
import de.governikus.datasign.cookbook.types.SignatureSerialization;
import de.governikus.datasign.cookbook.types.request.DocumentSignatureParameter;
import de.governikus.datasign.cookbook.types.request.DocumentToBeSigned;
import de.governikus.datasign.cookbook.types.request.SignatureDocumentTransactionRequest;
import de.governikus.datasign.cookbook.types.request.TanAuthorizeRequest;
import de.governikus.datasign.cookbook.types.response.DocumentSignTransaction;
import de.governikus.datasign.cookbook.types.response.UploadedDocument;
import de.governikus.datasign.cookbook.types.response.User;
import de.governikus.datasign.cookbook.util.DSSFactory;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.io.FileInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;

import static de.governikus.datasign.cookbook.util.AccessTokenUtil.retrieveAccessToken;

/**
 * Example for document signing.
 */
public class SignDocumentExample extends AbstractExample {

    public static void main(String[] args) throws Exception {
        new SignDocumentExample().runExample();
    }

    public void runExample() throws Exception {
        props.load(new FileInputStream("cookbook.properties"));
        System.out.println("Running example with properties = " + props);

        var provider = SignProvider.valueOf(props.getProperty("example.signProvider"));
        switch (provider) {
            case DTRUST -> runDTrustExample();
            case STORED_KEYS -> runStoredKeysExample();
            case SIGN8 -> runSign8Example();
            case NETCETERA ->
                    System.out.println("JAdES signature format is currently not supported with G+D Netcetera.");
        }
    }

    public void runDTrustExample() throws Exception {
        var accessToken = retrieveAccessToken(props);

        var provider = SignProvider.DTRUST;

        var userId = props.getProperty("example.userId");

        // GET /users/{userId}
        var user = send(
                GET("/users/%s".formatted(URLEncoder.encode(userId, StandardCharsets.UTF_8)))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                User.class);

        // ensure the user's account is ready for signing,
        // otherwise ask the user to visit the DATA Sign web application "Mein Konto" to register an account for the provider
        if (user.state() != User.State.READY) {
            System.err.println("The user account is not ready for signing. Please visit 'Mein Konto'.");
            return;
        }

        // POST /documents
        var uploadedDocument = send(POST("/documents", new String(new FileInputStream("sample.json").readAllBytes()))
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                UploadedDocument.class);

        // POST /sign/document/transactions
        var transaction = send(
                POST("/sign/document/transactions",
                        new SignatureDocumentTransactionRequest(
                                userId,
                                null,
                                new DocumentSignatureParameter(SignatureNiveau.QUALIFIED, SignatureLevel.B_B,
                                        HashAlgorithm.SHA_512, SignatureFormat.JADES, SignaturePackaging.ENVELOPING, SignatureSerialization.JWS_COMPACT),
                                // when redirectAfterPageVisitUrl is omitted, a fallback website is presented after the user's acknowledgment at the provider page
                                null,
                                null,
                                null,
                                List.of(new DocumentToBeSigned(uploadedDocument.documentId(), null, null))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentSignTransaction.class);

        System.out.println("the pending transaction has state = " + transaction.state());

        // perform 2FA by page visit
        if (transaction.state() == DocumentSignTransaction.State.PAGE_VISIT_REQUIRED) {
            System.out.println("The user must now acknowledgment the transaction by page visit to = " + transaction.pageVisitUrl());
            prompt("Press any key when page visit has been completed " +
                    "and the 'return to your application' website has been presented.");
        }

        // GET /sign/document/transactions/{id}
        transaction = send(
                GET("/sign/document/transactions/%s".formatted(transaction.id()))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentSignTransaction.class);

        if (transaction.state() == DocumentSignTransaction.State.FINISHED) {
            System.out.println("Transaction transitioned after 2FA into FINISHED state.");
        } else {
            System.err.println("Transaction did not transition into FINISHED state.");
            return;
        }

        var signedDocument = transaction.results().stream().filter(r ->
                r.documentId().equals(uploadedDocument.documentId())).findFirst().orElseThrow();
        var signedJWS = signedDocument.signedDocument();

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(new InMemoryDocument(new FileInputStream("sample.json")),
                new InMemoryDocument(signedJWS)).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(signedJWS, "sample_signed.json.jwt");
        System.out.println("sample.json is now signed and the signature is written to disk as sample_signed.json.jwt");
    }

    public void runSign8Example() throws Exception {
        var accessToken = retrieveAccessToken(props);

        var provider = SignProvider.SIGN8;

        var userId = props.getProperty("example.userId");

        // POST /documents
        var uploadedDocument = send(POST("/documents", new String(new FileInputStream("sample.json").readAllBytes()))
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                UploadedDocument.class);

        // POST /sign/document/transactions
        var transaction = send(
                POST("/sign/document/transactions",
                        new SignatureDocumentTransactionRequest(
                                userId,
                                null,
                                new DocumentSignatureParameter(SignatureNiveau.QUALIFIED, SignatureLevel.B_B,
                                        HashAlgorithm.SHA_512, SignatureFormat.JADES, SignaturePackaging.ENVELOPING, SignatureSerialization.JWS_COMPACT),
                                URI.create("https://www.governikus.de"),
                                null,
                                null,
                                List.of(new DocumentToBeSigned(uploadedDocument.documentId(), null, null))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentSignTransaction.class);

        System.out.println("the pending transaction has state = " + transaction.state());

        // acknowledge the transaction by page visit and retrieve code
        if (transaction.state() == DocumentSignTransaction.State.PAGE_VISIT_REQUIRED) {
            System.out.println("The user must now acknowledge the transaction by page visit to = " + transaction.pageVisitUrl());
            var code = prompt("Enter the <code> from your browser address bar www.governikus.de/?code=<code>:");

            // PUT /sign/document/transactions/{id}/2fa
            send(PUT("/sign/document/transactions/%s/2fa".formatted(transaction.id()),
                    new TanAuthorizeRequest(code))
                    .header("provider", provider.toString())
                    .header("Authorization", accessToken.toAuthorizationHeader()));
        }

        // GET /sign/document/transactions/{id}
        transaction = send(
                GET("/sign/document/transactions/%s".formatted(transaction.id()))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentSignTransaction.class);

        if (transaction.state() == DocumentSignTransaction.State.FINISHED) {
            System.out.println("Transaction transitioned into FINISHED state.");
        } else {
            System.err.println("Transaction did not transition into FINISHED state.");
            return;
        }

        var signedDocument = transaction.results().stream().filter(r ->
                r.documentId().equals(uploadedDocument.documentId())).findFirst().orElseThrow();
        var signedJWS = signedDocument.signedDocument();

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(new InMemoryDocument(new FileInputStream("sample.json")),
                new InMemoryDocument(signedJWS)).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(signedJWS, "sample_signed.json.jwt");
        System.out.println("sample.json is now signed and the signature is written to disk as sample_signed.json.jwt");
    }

    public void runStoredKeysExample() throws Exception {
        var accessToken = retrieveAccessToken(props);

        var provider = SignProvider.STORED_KEYS;
        var timestampProvider = props.getProperty("example.timestampProvider");

        var userId = props.getProperty("example.userId");

        // GET /users/{userId}
        var user = send(
                GET("/users/%s".formatted(URLEncoder.encode(userId, StandardCharsets.UTF_8)))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                User.class);

        // ensure the user's account is ready for signing,
        // otherwise ask the user to visit the DATA Sign web application "Mein Konto" to upload key material
        if (user.state() != User.State.READY) {
            System.err.println("The user account is not ready for signing. Please visit 'Mein Konto'.");
            return;
        }

        // discover which certificates are available to the user
        System.out.println("user's certificates  = " + user.certificates());

        // here we use the certificate from our cookbook.properties file, make sure it exists
        var certificateId = props.getProperty("example.certificateId");

        // POST /documents
        var uploadedDocument = send(POST("/documents", new String(new FileInputStream("sample.json").readAllBytes()))
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                UploadedDocument.class);

        // POST /sign/document/transactions
        var transaction = send(
                POST("/sign/document/transactions",
                        new SignatureDocumentTransactionRequest(
                                userId,
                                UUID.fromString(certificateId),
                                new DocumentSignatureParameter(SignatureNiveau.ADVANCED, SignatureLevel.B_LT,
                                        HashAlgorithm.SHA_256, SignatureFormat.JADES, SignaturePackaging.ENVELOPING, SignatureSerialization.JWS_JSON),
                                null,
                                null,
                                timestampProvider,
                                List.of(new DocumentToBeSigned(uploadedDocument.documentId(), null, null))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentSignTransaction.class);

        var signedDocument = transaction.results().stream().filter(r ->
                r.documentId().equals(uploadedDocument.documentId())).findFirst().orElseThrow();
        var signedJWS = signedDocument.signedDocument();

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(new InMemoryDocument(new FileInputStream("sample.json")),
                new InMemoryDocument(signedJWS)).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(signedJWS, "sample_signed.json");
        System.out.println("sample.json is now signed and the signature is written to disk as sample_signed.json");
    }

    private String prompt(String toDisplay) {
        System.out.println(toDisplay);
        return new Scanner(System.in).nextLine().trim();
    }

}
