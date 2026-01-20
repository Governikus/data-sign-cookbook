package de.governikus.datasign.cookbook.cades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.*;
import de.governikus.datasign.cookbook.types.request.*;
import de.governikus.datasign.cookbook.types.response.DocumentHashSignTransaction;
import de.governikus.datasign.cookbook.types.response.DocumentSignTransaction;
import de.governikus.datasign.cookbook.types.response.UploadedDocument;
import de.governikus.datasign.cookbook.types.response.User;
import de.governikus.datasign.cookbook.util.DSSFactory;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.io.FileInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;

import static de.governikus.datasign.cookbook.util.AccessTokenUtil.retrieveAccessToken;

/**
 * Example for document hash signing.
 */
public class SignDocumentHashExample extends AbstractExample {

    public static void main(String[] args) throws Exception {
        new SignDocumentHashExample().runExample();
    }

    public void runExample() throws Exception {
        props.load(new FileInputStream("cookbook.properties"));
        System.out.println("Running example with properties = " + props.getProperty("url"));

        var provider = SignProvider.valueOf(props.getProperty("example.signProvider"));
        switch (provider) {
            case BV -> runBankVerlagExample();
            case DTRUST -> runDTrustExample();
            case STORED_KEYS -> runStoredKeysExample();
        }
    }

    public void runBankVerlagExample() throws Exception {
        var accessToken = retrieveAccessToken(props);

        var provider = SignProvider.BV;

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

        // confirm that the identity information provided to us is up to date.
        boolean confirmsIdentity = false;
        if (user.needsRecurringConfirmationOfIdentity()) {
            printIdentificationDocument(user.identificationDocument());
            if (prompt("Enter 'y' to confirm identity or cancel transaction:").trim().equals("y")) {
                confirmsIdentity = true;
            }
        }

        // calculate the document hash from the unsigned document
        var documentHash = MessageDigest.getInstance("SHA-256").digest(new FileInputStream("sample.docx").readAllBytes());

        // POST /sign/document-hash/transactions
        var documentHashId = UUID.randomUUID();
        var transaction = send(
                POST("/sign/document-hash/transactions",
                        new SignatureDocumentHashTransactionRequest(
                                userId,
                                null,
                                new DocumentSignatureParameter(SignatureNiveau.ADVANCED, SignatureLevel.B_LT,
                                        HashAlgorithm.SHA_256, SignatureFormat.CADES, SignaturePackaging.DETACHED),
                                null,
                                confirmsIdentity,
                                null,
                                List.of(new DocumentHash(documentHashId, documentHash))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentHashSignTransaction.class);

        System.out.println("the pending transaction has state = " + transaction.state());

        // perform 2FA by TAN
        if (transaction.state() == DocumentHashSignTransaction.State.TAN_REQUIRED) {
            System.out.println("TAN has been send to = " + transaction.tanSendTo());
            var tan = prompt("Enter TAN:");

            // PUT /sign/document-hash/transactions/{id}/2fa
            send(PUT("/sign/document-hash/transactions/%s/2fa".formatted(transaction.id()),
                    new TanAuthorizeRequest(tan))
                    .header("provider", provider.toString())
                    .header("Authorization", accessToken.toAuthorizationHeader()));
        }

        // GET /sign/document-hash/transactions/{id}
        transaction = send(
                GET("/sign/document-hash/transactions/%s".formatted(transaction.id()))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentHashSignTransaction.class);

        if (transaction.state() == DocumentHashSignTransaction.State.FINISHED) {
            System.out.println("Transaction transitioned after 2FA into FINISHED state.");
        } else {
            System.err.println("Transaction did not transition into FINISHED state.");
            return;
        }

        var cmsSignedData = transaction.results().stream().filter(r ->
                r.id().equals(documentHashId)).findFirst().orElseThrow();

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(new InMemoryDocument(new FileInputStream("sample.docx")),
                new InMemoryDocument(cmsSignedData.cmsSignedData())).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(cmsSignedData.cmsSignedData(), "sample_signed.docx.p7s");
        System.out.println("sample.docx is now signed and the signature is written to disk as sample_signed.docx.p7s");
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

        // calculate the document hash from the unsigned document
        var documentHash = MessageDigest.getInstance("SHA-256").digest(new FileInputStream("sample.docx").readAllBytes());

        // POST /sign/document-hash/transactions
        var documentHashId = UUID.randomUUID();
        var transaction = send(
                POST("/sign/document-hash/transactions",
                        new SignatureDocumentHashTransactionRequest(
                                userId,
                                null,
                                new DocumentSignatureParameter(SignatureNiveau.QUALIFIED, SignatureLevel.B_LT,
                                        HashAlgorithm.SHA_256, SignatureFormat.CADES, SignaturePackaging.DETACHED),
                                // when redirectAfterPageVisitUrl is omitted, a fallback website is presented after the user's acknowledgment at the provider page
                                null,
                                null,
                                null,
                                List.of(new DocumentHash(documentHashId, documentHash))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentHashSignTransaction.class);

        System.out.println("the pending transaction has state = " + transaction.state());

        // perform 2FA by page visit
        if (transaction.state() == DocumentHashSignTransaction.State.PAGE_VISIT_REQUIRED) {
            System.out.println("The user must now acknowledgment the transaction by page visit to = " + transaction.pageVisitUrl());
            prompt("Press any key when page visit has been completed " +
                    "and the 'return to your application' website has been presented.");
        }

        // GET /sign/document-hash/transactions/{id}
        transaction = send(
                GET("/sign/document-hash/transactions/%s".formatted(transaction.id()))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentHashSignTransaction.class);

        if (transaction.state() == DocumentHashSignTransaction.State.FINISHED) {
            System.out.println("Transaction transitioned after 2FA into FINISHED state.");
        } else {
            System.err.println("Transaction did not transition into FINISHED state.");
            return;
        }

        var cmsSignedData = transaction.results().stream().filter(r ->
                r.id().equals(documentHashId)).findFirst().orElseThrow();

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(new InMemoryDocument(new FileInputStream("sample.docx")),
                new InMemoryDocument(cmsSignedData.cmsSignedData())).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(cmsSignedData.cmsSignedData(), "sample_signed.docx.p7s");
        System.out.println("sample.docx is now signed and the signature is written to disk as sample_signed.docx.p7s");
    }

    public void runStoredKeysExample() throws Exception {
        var accessToken = retrieveAccessToken(props);

        var provider = SignProvider.STORED_KEYS;
        var timestampProvider = props.getProperty("example.timestampProvider");

        var userId = props.getProperty("example.userId");
        var certificateId = props.getProperty("example.certificateId");

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

        // calculate the document hash from the unsigned document
        var documentHash = MessageDigest.getInstance("SHA-256").digest(new FileInputStream("sample.docx").readAllBytes());

        // POST /sign/document-hash/transactions
        var documentHashId = UUID.randomUUID();
        var transaction = send(
                POST("/sign/document-hash/transactions",
                        new SignatureDocumentHashTransactionRequest(
                                userId,
                                UUID.fromString(certificateId),
                                new DocumentSignatureParameter(SignatureNiveau.ADVANCED, SignatureLevel.B_LT,
                                        HashAlgorithm.SHA_256, SignatureFormat.CADES, SignaturePackaging.DETACHED),
                                null,
                                null,
                                timestampProvider,
                                List.of(new DocumentHash(documentHashId, documentHash))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentHashSignTransaction.class);

        var cmsSignedData = transaction.results().stream().filter(r ->
                r.id().equals(documentHashId)).findFirst().orElseThrow();

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(new InMemoryDocument(new FileInputStream("sample.docx")),
                new InMemoryDocument(cmsSignedData.cmsSignedData())).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(cmsSignedData.cmsSignedData(), "sample_signed.docx.p7s");
        System.out.println("sample.docx is now signed and the signature is written to disk as sample_signed.docx.p7s");
    }

    private String prompt(String toDisplay) {
        System.out.println(toDisplay);
        return new Scanner(System.in).nextLine().trim();
    }

    private void printIdentificationDocument(User.IdentificationDocument identificationDocument) {
        System.out.println("Please check your identification document");
        System.out.printf("Name: %s %s %n", identificationDocument.givenName(), identificationDocument.familyName());
        System.out.printf("Birthdate: %s %n", identificationDocument.birthDate());
        System.out.printf("Address: %s, %s, %s %n", identificationDocument.addressLine(), identificationDocument.cityLine(), identificationDocument.countryCodeIso2());
        System.out.printf("Expires on: %s %n", identificationDocument.expiresOn());
    }
}
