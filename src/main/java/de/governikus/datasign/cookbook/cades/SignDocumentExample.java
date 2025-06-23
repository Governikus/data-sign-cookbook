package de.governikus.datasign.cookbook.cades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.*;
import de.governikus.datasign.cookbook.types.request.*;
import de.governikus.datasign.cookbook.types.response.DocumentSignTransaction;
import de.governikus.datasign.cookbook.types.response.UploadedDocument;
import de.governikus.datasign.cookbook.types.response.UserState;

import java.io.FileInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Scanner;

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
        System.out.println("Running example with properties = " + props.getProperty("url"));

        var accessToken = retrieveAccessToken(props);

        var provider = Provider.valueOf(props.getProperty("example.provider"));

        var userId = props.getProperty("example.userId");

        // GET /users/{userId}/state
        var userState = send(
                GET("/users/%s/state".formatted(URLEncoder.encode(userId, StandardCharsets.UTF_8)))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                UserState.class);

        // ensure the user's account is ready for signing,
        // otherwise ask the user to visit the DATA Sign web application "Mein Konto" to register an account for the provider
        if (userState.state() != UserState.State.READY) {
            System.err.println("The user account is not ready for signing. Please visit 'Mein Konto'.");
            return;
        }

        // POST /documents
        var uploadedDocument = send(POST("/documents", new FileInputStream("sample.pdf").readAllBytes())
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                UploadedDocument.class);

        // POST /sign/document/transactions
        var transaction = send(
                POST("/sign/document/transactions",
                        new SignatureDocumentTransactionRequest(
                                userId,
                                new DocumentSignatureParameter(SignatureNiveau.QUALIFIED, SignatureLevel.B_LT,
                                        HashAlgorithm.SHA_256, SignatureFormat.CADES, SignaturePackaging.ENVELOPING),
                                // when redirectAfterPageVisitUrl is omitted, a fallback website is presented after the user's acknowledgment at the provider page
                                null,
                                List.of(new DocumentToBeSigned(uploadedDocument.documentId(), null, null))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentSignTransaction.class);

        System.out.println("the pending transaction has state = " + transaction.state());

        // the 2FA the user must perform depends on the provider...
        // ...either by TAN
        if (transaction.state() == DocumentSignTransaction.State.TAN_REQUIRED) {
            System.out.println("TAN has been send to = " + transaction.tanSendTo());
            var tan = prompt("Enter TAN:");

            // PUT /sign/document/transactions/{id}/2fa
            send(PUT("/sign/document/transactions/%s/2fa".formatted(transaction.id()),
                    new TanAuthorizeRequest(tan))
                    .header("provider", provider.toString())
                    .header("Authorization", accessToken.toAuthorizationHeader()));
        }

        // ...or by page visit
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

        var result = transaction.results().stream().filter(r ->
                r.documentId().equals(uploadedDocument.documentId())).findFirst().orElseThrow();

        // GET /documents/{documentId}/signatures/{signatureId}
        var documentRevisionBytes = retrieveBytes(GET(result.href().toString())
                .header("Authorization", accessToken.toAuthorizationHeader()));


        writeToDisk(documentRevisionBytes, "sample_signed.pdf.p7s");
        System.out.println("sample.pdf is now signed and the signature is written to disk as sample_signed.pdf.p7s");
    }

    private String prompt(String toDisplay) {
        System.out.println(toDisplay);
        return new Scanner(System.in).nextLine().trim();
    }

}
