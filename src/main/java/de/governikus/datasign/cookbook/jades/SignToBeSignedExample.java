package de.governikus.datasign.cookbook.jades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.HashAlgorithm;
import de.governikus.datasign.cookbook.types.SignProvider;
import de.governikus.datasign.cookbook.types.SignatureAlgorithm;
import de.governikus.datasign.cookbook.types.SignatureNiveau;
import de.governikus.datasign.cookbook.types.request.SignatureToBeSignedTransactionRequest;
import de.governikus.datasign.cookbook.types.request.ToBeSigned;
import de.governikus.datasign.cookbook.types.request.ToBeSignedSignatureParameter;
import de.governikus.datasign.cookbook.types.response.Certificate;
import de.governikus.datasign.cookbook.types.response.ToBeSignedSignTransaction;
import de.governikus.datasign.cookbook.types.response.User;
import de.governikus.datasign.cookbook.util.DSSFactory;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.io.FileInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;

import static de.governikus.datasign.cookbook.util.AccessTokenUtil.retrieveAccessToken;

/**
 * Example for CAdES to-be-signed based signing. This is more low level than signing documents.
 */
public class SignToBeSignedExample extends AbstractExample {

    public static void main(String[] args) throws Exception {
        new SignToBeSignedExample().runExample();
    }

    public void runExample() throws Exception {
        props.load(new FileInputStream("cookbook.properties"));
        System.out.println("Running example with properties = " + props);

        var provider = SignProvider.valueOf(props.getProperty("example.signProvider"));
        switch (provider) {
            case DTRUST -> runDTrustExample();
            case STORED_KEYS -> runStoredKeysExample();
            case NETCETERA -> System.out.println("Signing to-be-signed with G+D Netcetera is not supported.");
            case SIGN8 -> System.out.println("Signing to-be-signed with SIGN8 is not supported.");
        }
    }

    public void runDTrustExample() throws Exception {
        var accessToken = retrieveAccessToken(props);

        var provider = SignProvider.DTRUST;

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

        // Use these to discover which signature algorithms are available and pick one
        System.out.println("signatureAlgorithms = " + certificate.signatureAlgorithms());

        // here we use the signatureAlgorithm from our cookbook.properties file, make sure the signature algorithm is supported
        var signatureAlgorithm = SignatureAlgorithm.valueOf(props.getProperty("example.signatureAlgorithm"));
        var hashAlgorithm = hashAlgorithm(signatureAlgorithm);

        // calculate the DTBS from the unsigned document
        var unsignedDocument = new InMemoryDocument(new FileInputStream("sample.json"));

        var jAdESService = DSSFactory.jAdESService();
        var signatureParameter = signatureParameters(certificate.certificate(), signatureAlgorithm, hashAlgorithm);
        var dtbs = jAdESService.getDataToSign(unsignedDocument, signatureParameter);

        // POST /sign/to-be-signed/transactions
        var toBeSignedId = UUID.randomUUID();
        var transaction = send(
                POST("/sign/to-be-signed/transactions",
                        new SignatureToBeSignedTransactionRequest(
                                userId,
                                null,
                                new ToBeSignedSignatureParameter(SignatureNiveau.QUALIFIED, hashAlgorithm, null),
                                // when redirectAfterPageVisitUrl is omitted, a fallback website is presented after the user's acknowledgment at the provider page
                                null,
                                List.of(new ToBeSigned(toBeSignedId, dtbs.getBytes(), "sample.json"))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                ToBeSignedSignTransaction.class);

        System.out.println("the pending transaction has state = " + transaction.state());

        // perform 2FA by page visit
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

        // use the signature value to generate a JWS signature
        var signedDocument = jAdESService.signDocument(unsignedDocument, signatureParameter,
                new SignatureValue(mapSignatureAlgorithm(signatureAlgorithm), signatureValue.signatureValue()));

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(unsignedDocument, signedDocument).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(((InMemoryDocument) signedDocument).getBytes(), "sample_signed.json.jwt");
        System.out.println("sample.json is now sealed and the JWS signature is written to disk as sample_signed.json.jwt");
    }

    public void runStoredKeysExample() throws Exception {
        var accessToken = retrieveAccessToken(props);

        var provider = SignProvider.STORED_KEYS;

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

        // GET /users/{userId}/certificates/{certificateId}
        var certificate = send(
                GET("/users/%s/certificates/%s".formatted(URLEncoder.encode(userId, StandardCharsets.UTF_8), URLEncoder.encode(certificateId, StandardCharsets.UTF_8)))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                Certificate.class);

        // Use these to discover which signature algorithms are available and pick one
        System.out.println("signatureAlgorithms = " + certificate.signatureAlgorithms());

        // here we use the signatureAlgorithm from our cookbook.properties file, make sure the signature algorithm is supported
        var signatureAlgorithm = SignatureAlgorithm.valueOf(props.getProperty("example.signatureAlgorithm"));
        var hashAlgorithm = hashAlgorithm(signatureAlgorithm);

        // calculate the DTBS from the unsigned document
        var unsignedDocument = new InMemoryDocument(new FileInputStream("sample.json"));

        var jAdESService = DSSFactory.jAdESService();
        var signatureParameter = signatureParameters(certificate.certificate(), signatureAlgorithm, hashAlgorithm);
        var dtbs = jAdESService.getDataToSign(unsignedDocument, signatureParameter);

        // POST /sign/to-be-signed/transactions
        var toBeSignedId = UUID.randomUUID();
        var transaction = send(
                POST("/sign/to-be-signed/transactions",
                        new SignatureToBeSignedTransactionRequest(
                                userId,
                                UUID.fromString(certificateId),
                                new ToBeSignedSignatureParameter(SignatureNiveau.ADVANCED, hashAlgorithm, signatureAlgorithm),
                                null,
                                List.of(new ToBeSigned(toBeSignedId, dtbs.getBytes(), "sample.pdf"))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                ToBeSignedSignTransaction.class);

        System.out.println("the pending transaction has state = " + transaction.state());

        var signatureValue = transaction.results().values().stream()
                .filter(v -> v.id().equals(toBeSignedId)).findFirst().orElseThrow();

        // use the signature value to generate a JWS signature
        var signedDocument = jAdESService.signDocument(unsignedDocument, signatureParameter,
                new SignatureValue(mapSignatureAlgorithm(signatureAlgorithm), signatureValue.signatureValue()));

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(unsignedDocument, signedDocument).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(((InMemoryDocument) signedDocument).getBytes(), "sample_signed.json.jwt");
        System.out.println("sample.json is now signed and the detached signature is written to disk as sample_signed.json.jwt");
    }

    private static JAdESSignatureParameters signatureParameters(byte[] signingCertificate, SignatureAlgorithm signatureAlgorithm, HashAlgorithm hashAlgorithm) throws Exception {
        var jAdESSignatureParameters = new JAdESSignatureParameters();
        jAdESSignatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        jAdESSignatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        jAdESSignatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        jAdESSignatureParameters.setDigestAlgorithm(switch (hashAlgorithm) {
            case SHA_256 -> DigestAlgorithm.SHA256;
            case SHA_384 -> DigestAlgorithm.SHA384;
            case SHA_512 -> DigestAlgorithm.SHA512;
        });
        jAdESSignatureParameters.setSigningCertificate(new CertificateToken(toX509Certificate(signingCertificate)));
        // leave #setEncryptionAlgorithm here after #setSigningCertificate
        jAdESSignatureParameters.setEncryptionAlgorithm(switch (signatureAlgorithm) {
            case RSA_SHA256, RSA_SHA384, RSA_SHA512 -> EncryptionAlgorithm.RSA;
            case RSA_WITH_MGF1_SHA256, RSA_WITH_MGF1_SHA384, RSA_WITH_MGF1_SHA512 -> EncryptionAlgorithm.RSASSA_PSS;
            case ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512 -> EncryptionAlgorithm.ECDSA;
            case PLAIN_ECDSA_SHA256, PLAIN_ECDSA_SHA384, PLAIN_ECDSA_SHA512 -> EncryptionAlgorithm.PLAIN_ECDSA;
        });
        return jAdESSignatureParameters;
    }

    private static eu.europa.esig.dss.enumerations.SignatureAlgorithm mapSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        return switch (signatureAlgorithm) {
            case RSA_WITH_MGF1_SHA256 -> eu.europa.esig.dss.enumerations.SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1;
            case RSA_WITH_MGF1_SHA384 -> eu.europa.esig.dss.enumerations.SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1;
            case RSA_WITH_MGF1_SHA512 -> eu.europa.esig.dss.enumerations.SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1;
            case RSA_SHA256 -> eu.europa.esig.dss.enumerations.SignatureAlgorithm.RSA_SHA256;
            case RSA_SHA384 -> eu.europa.esig.dss.enumerations.SignatureAlgorithm.RSA_SHA384;
            case RSA_SHA512 -> eu.europa.esig.dss.enumerations.SignatureAlgorithm.RSA_SHA512;
            case ECDSA_SHA256 -> eu.europa.esig.dss.enumerations.SignatureAlgorithm.ECDSA_SHA256;
            case ECDSA_SHA384 -> eu.europa.esig.dss.enumerations.SignatureAlgorithm.ECDSA_SHA384;
            case ECDSA_SHA512 -> eu.europa.esig.dss.enumerations.SignatureAlgorithm.ECDSA_SHA512;
            case PLAIN_ECDSA_SHA256 -> eu.europa.esig.dss.enumerations.SignatureAlgorithm.PLAIN_ECDSA_SHA256;
            case PLAIN_ECDSA_SHA384 -> eu.europa.esig.dss.enumerations.SignatureAlgorithm.PLAIN_ECDSA_SHA384;
            case PLAIN_ECDSA_SHA512 -> eu.europa.esig.dss.enumerations.SignatureAlgorithm.PLAIN_ECDSA_SHA512;
        };
    }

    private static HashAlgorithm hashAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        return switch (signatureAlgorithm) {
            case RSA_SHA256, RSA_WITH_MGF1_SHA256, ECDSA_SHA256, PLAIN_ECDSA_SHA256 -> HashAlgorithm.SHA_256;
            case RSA_SHA384, RSA_WITH_MGF1_SHA384, ECDSA_SHA384, PLAIN_ECDSA_SHA384 -> HashAlgorithm.SHA_384;
            case RSA_SHA512, RSA_WITH_MGF1_SHA512, ECDSA_SHA512, PLAIN_ECDSA_SHA512 -> HashAlgorithm.SHA_512;
        };
    }

    private String prompt(String toDisplay) {
        System.out.println(toDisplay);
        return new Scanner(System.in).nextLine().trim();
    }

}
