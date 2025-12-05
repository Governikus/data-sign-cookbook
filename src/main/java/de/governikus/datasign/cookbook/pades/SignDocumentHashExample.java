package de.governikus.datasign.cookbook.pades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.*;
import de.governikus.datasign.cookbook.types.request.*;
import de.governikus.datasign.cookbook.types.response.DocumentHashSignTransaction;
import de.governikus.datasign.cookbook.types.response.DocumentSignTransaction;
import de.governikus.datasign.cookbook.types.response.UploadedDocument;
import de.governikus.datasign.cookbook.types.response.User;
import de.governikus.datasign.cookbook.util.DSSFactory;
import eu.europa.esig.dss.cms.CMSSignedDocument;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.spi.DSSUtils;

import java.io.FileInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
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

        var accessToken = retrieveAccessToken(props);

        var provider = SignProvider.valueOf(props.getProperty("example.signProvider"));

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
        var unsignedDocument = new InMemoryDocument(new FileInputStream("sample.pdf"));

        var signatureParameter = signatureParameter(HashAlgorithm.SHA_256);
        var documentHash = DSSFactory.pAdESWithExternalCMSService().getMessageDigest(unsignedDocument, signatureParameter).getValue();

        // POST /sign/document-hash/transactions
        var documentHashId = UUID.randomUUID();
        var transaction = send(
                POST("/sign/document-hash/transactions",
                        new SignatureDocumentHashTransactionRequest(
                                userId,
                                new DocumentSignatureParameter(SignatureNiveau.QUALIFIED, SignatureLevel.B_LT,
                                        HashAlgorithm.SHA_256, SignatureFormat.PADES, SignaturePackaging.ENVELOPED),
                                // when redirectAfterPageVisitUrl is omitted, a fallback website is presented after the user's acknowledgment at the provider page
                                null,
                                confirmsIdentity,
                                List.of(new DocumentHash(documentHashId,
                                        documentHash))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentHashSignTransaction.class);

        System.out.println("the pending transaction has state = " + transaction.state());

        // the 2FA the user must perform depends on the provider...
        // ...either by TAN
        if (transaction.state() == DocumentHashSignTransaction.State.TAN_REQUIRED) {
            System.out.println("TAN has been send to = " + transaction.tanSendTo());
            var tan = prompt("Enter TAN:");

            // PUT /sign/document/transactions/{id}/2fa
            send(PUT("/sign/document-hash/transactions/%s/2fa".formatted(transaction.id()),
                    new TanAuthorizeRequest(tan))
                    .header("provider", provider.toString())
                    .header("Authorization", accessToken.toAuthorizationHeader()));
        }

        // ...or by page visit
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

        var cmsSignedData = transaction.results().stream()
                .filter(v -> v.id().equals(documentHashId)).findFirst().orElseThrow();

        // use the cms signed data to incorporate a signature into the unsigned document
        var cmsSignedDocument = new CMSSignedDocument(DSSUtils.toCMSSignedData(cmsSignedData.cmsSignedData()));
        var signedDocument = DSSFactory.pAdESWithExternalCMSService().signDocument(unsignedDocument, signatureParameter, cmsSignedDocument);

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(new InMemoryDocument(new FileInputStream("sample.pdf")),
                signedDocument).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(signedDocument, "sample_signed.pdf");
        System.out.println("sample.pdf is now signed and written to disk as sample_signed.pdf");
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

    private static PAdESSignatureParameters signatureParameter(HashAlgorithm hashAlgorithm) {
        var pAdESSignatureParameters = new PAdESSignatureParameters();
        pAdESSignatureParameters.setDigestAlgorithm(switch (hashAlgorithm) {
            case SHA_256 -> DigestAlgorithm.SHA256;
            case SHA_384 -> DigestAlgorithm.SHA384;
            case SHA_512 -> DigestAlgorithm.SHA512;
        });
        pAdESSignatureParameters.setSignatureLevel(eu.europa.esig.dss.enumerations.SignatureLevel.PAdES_BASELINE_T);
        pAdESSignatureParameters.setContentSize(14_500);
        return pAdESSignatureParameters;
    }
}
