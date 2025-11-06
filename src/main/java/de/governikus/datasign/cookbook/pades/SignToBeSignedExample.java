package de.governikus.datasign.cookbook.pades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.*;
import de.governikus.datasign.cookbook.types.request.*;
import de.governikus.datasign.cookbook.types.response.*;
import de.governikus.datasign.cookbook.util.DSSFactory;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;

import java.io.FileInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;

import static de.governikus.datasign.cookbook.util.AccessTokenUtil.retrieveAccessToken;

/**
 * Example for to-be-signed based signing. This is more low level than signing documents.
 */
public class SignToBeSignedExample extends AbstractExample {

    public static void main(String[] args) throws Exception {
        new SignToBeSignedExample().runExample();
    }

    public void runExample() throws Exception {
        props.load(new FileInputStream("cookbook.properties"));
        System.out.println("Running example with properties = " + props.getProperty("url"));

        var accessToken = retrieveAccessToken(props);

        var provider = SignProvider.valueOf(props.getProperty("example.signProvider"));

        var timestampProvider = props.getProperty("example.timestampProvider");

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

        // GET /users/{userId}/certificates
        var certificate = send(
                GET("/users/%s/certificates".formatted(URLEncoder.encode(userId, StandardCharsets.UTF_8)))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                Certificate.class);

        // calculate the DTBS from the unsigned document
        var unsignedDocument = new InMemoryDocument(new FileInputStream("sample.pdf"));

        var signatureParameter = signatureParameter(provider, certificate.certificate());
        var dtbs = DSSFactory.pAdESService().getDataToSign(unsignedDocument, signatureParameter);

        // POST /sign/to-be-signed/transactions
        var toBeSignedId = UUID.randomUUID();
        var transaction = send(
                POST("/sign/to-be-signed/transactions",
                        new SignatureToBeSignedTransactionRequest(
                                userId,
                                new ToBeSignedSignatureParameter(SignatureNiveau.QUALIFIED, HashAlgorithm.SHA_256),
                                // when redirectAfterPageVisitUrl is omitted, a fallback website is presented after the user's acknowledgment at the provider page
                                null,
                                List.of(new ToBeSigned(toBeSignedId, dtbs.getBytes(), "sample.pdf"))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                ToBeSignedSignTransaction.class);

        System.out.println("the pending transaction has state = " + transaction.state());

        // the 2FA the user must perform depends on the provider...
        // ...either by TAN
        if (transaction.state() == ToBeSignedSignTransaction.State.TAN_REQUIRED) {
            System.out.println("TAN has been send to = " + transaction.tanSendTo());
            var tan = prompt("Enter TAN:");

            // PUT /sign/to-be-signed/transactions/{id}/2fa
            send(PUT("/sign/to-be-signed/transactions/%s/2fa".formatted(transaction.id()),
                    new TanAuthorizeRequest(tan))
                    .header("provider", provider.toString())
                    .header("Authorization", accessToken.toAuthorizationHeader()));
        }

        // ...or by page visit
        if (transaction.state() == ToBeSignedSignTransaction.State.PAGE_VISIT_REQUIRED) {
            System.out.println("The user must now acknowledgment the transaction by page visit to = " + transaction.pageVisitUrl());
            prompt("Press any key when page visit has been completed " +
                    "and the 'return to your application' website has been presented.");
        }

        // GET /sign/to-be-signed/transactions/{id}
        transaction = send(
                GET("/sign/to-be-signed/transactions/%s".formatted(transaction.id()))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                ToBeSignedSignTransaction.class);

        if (transaction.state() == ToBeSignedSignTransaction.State.FINISHED) {
            System.out.println("Transaction transitioned after 2FA into FINISHED state.");
        } else {
            System.err.println("Transaction did not transition into FINISHED state.");
            return;
        }

        var signatureValue = transaction.results().values().stream()
                .filter(v -> v.id().equals(toBeSignedId)).findFirst().orElseThrow();

        // POST /timestamp
        var digest = digest(HashAlgorithm.SHA_256, signatureValue.signatureValue());
        var timestamps = send(
                POST("/timestamp",
                        new TimestampRequest(timestampProvider, List.of(new Digest(signatureValue.id(),
                                HashAlgorithm.SHA_256, digest))))
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                Timestamps.class);

        var timestamp = timestamps.timestamps().stream()
                .filter(t -> t.id().equals(signatureValue.id())).findFirst().orElseThrow();

        // use the signature value to incorporate a signature into the unsigned document
        var signature = new SignatureValue(signatureParameter.getSignatureAlgorithm(), signatureValue.signatureValue());
        var signedDocument = DSSFactory.pAdESService(timestamp.timestampToken())
                .signDocument(unsignedDocument, signatureParameter, signature);

        if (!DSSFactory.pAdESService().isValidSignatureValue(dtbs, signature, new CertificateToken(toX509Certificate(certificate.certificate())))) {
            System.err.println("signatureValue is not coherent with document digest");
            return;
        }

        // extend signature to LT-Level
        signedDocument = DSSFactory.pAdESExtensionService().incorporateValidationData(signedDocument, null, true);

        DSSFactory.signedDocumentValidator(unsignedDocument, signedDocument).validateDocument();

        writeToDisk(signedDocument, "sample_signed.pdf");
        System.out.println("sample.pdf is now signed and written to disk as sample_signed.pdf");
    }

    private static PAdESSignatureParameters signatureParameter(SignProvider provider, byte[] signingCertificate) throws Exception {
        var pAdESSignatureParameters = new PAdESSignatureParameters();
        pAdESSignatureParameters.setSigningCertificate(new CertificateToken(toX509Certificate(signingCertificate)));
        // leave #setEncryptionAlgorithm here after #setSigningCertificate
        pAdESSignatureParameters.setEncryptionAlgorithm(switch (provider) {
            case BV -> EncryptionAlgorithm.RSASSA_PSS;
            case DTRUST -> EncryptionAlgorithm.ECDSA;
        });
        pAdESSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        pAdESSignatureParameters.setSignatureLevel(eu.europa.esig.dss.enumerations.SignatureLevel.PAdES_BASELINE_T);
        pAdESSignatureParameters.setContentSize(14_500);
        return pAdESSignatureParameters;
    }

    private String prompt(String toDisplay) {
        System.out.println(toDisplay);
        return new Scanner(System.in).nextLine().trim();
    }

    private static byte[] digest(HashAlgorithm hashAlgorithm, byte[] signatureValue) throws Exception {
        var hashAlgorithmJavaName = switch (hashAlgorithm) {
            case SHA_256 -> "SHA-256";
            case SHA_384 -> "SHA-384";
            case SHA_512 -> "SHA-512";
        };
        return MessageDigest.getInstance(hashAlgorithmJavaName).digest(signatureValue);
    }
}
