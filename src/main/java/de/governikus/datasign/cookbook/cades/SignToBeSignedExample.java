package de.governikus.datasign.cookbook.cades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.HashAlgorithm;
import de.governikus.datasign.cookbook.types.Provider;
import de.governikus.datasign.cookbook.types.SignatureLevel;
import de.governikus.datasign.cookbook.types.SignatureNiveau;
import de.governikus.datasign.cookbook.types.request.SignatureToBeSignedTransactionRequest;
import de.governikus.datasign.cookbook.types.request.TanAuthorizeRequest;
import de.governikus.datasign.cookbook.types.request.ToBeSigned;
import de.governikus.datasign.cookbook.types.request.ToBeSignedSignatureParameter;
import de.governikus.datasign.cookbook.types.response.Certificate;
import de.governikus.datasign.cookbook.types.response.ToBeSignedSignTransaction;
import de.governikus.datasign.cookbook.types.response.UserState;
import de.governikus.datasign.cookbook.util.DSSFactory;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;

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

        // GET /users/{userId}/certificates
        var certificate = send(
                GET("/users/%s/certificates".formatted(URLEncoder.encode(userId, StandardCharsets.UTF_8)))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                Certificate.class);

        // calculate the DTBS from the unsigned document
        var unsignedDocument = new InMemoryDocument(new FileInputStream("sample.docx"));

        var cAdESService = DSSFactory.cAdESService();
        var signatureParameter = signatureParameters(provider, certificate.certificate());
        var dtbs = cAdESService.getDataToSign(unsignedDocument, signatureParameter);

        // POST /sign/to-be-signed/transactions
        var toBeSignedId = UUID.randomUUID();
        var transaction = send(
                POST("/sign/to-be-signed/transactions",
                        new SignatureToBeSignedTransactionRequest(
                                userId,
                                new ToBeSignedSignatureParameter(SignatureNiveau.QUALIFIED, SignatureLevel.B_LT, HashAlgorithm.SHA_256),
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

        var signatureValueWithTimestamp = transaction.results().values().stream()
                .filter(v -> v.id().equals(toBeSignedId)).findFirst().orElseThrow();

        // use the signature value to generate a detached signature
        cAdESService.setTspSource(new DSSFactory.OnlyOnceTspSource(new TimeStampToken(new CMSSignedData(signatureValueWithTimestamp.timestamp()))));
        var signedDocument = cAdESService.signDocument(unsignedDocument, signatureParameter,
                new SignatureValue(signatureAlgorithm(provider), signatureValueWithTimestamp.signatureValue()));
        var detachedSignature = DSSUtils.toCMSSignedData(signedDocument).getEncoded();

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(unsignedDocument, signedDocument).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(detachedSignature, "sample_signed.docx.p7s");
        System.out.println("sample.docx is now signed and the detached signature is written to disk as sample_signed.docx.p7s");
    }

    private static CAdESSignatureParameters signatureParameters(Provider provider, byte[] signingCertificate) throws Exception {
        var cAdESSignatureParameters = new CAdESSignatureParameters();
        cAdESSignatureParameters.setSignatureLevel(eu.europa.esig.dss.enumerations.SignatureLevel.CAdES_BASELINE_LT);
        cAdESSignatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        cAdESSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        cAdESSignatureParameters.setSigningCertificate(new CertificateToken(toX509Certificate(signingCertificate)));
        // leave #setEncryptionAlgorithm here after #setSigningCertificate
        cAdESSignatureParameters.setEncryptionAlgorithm(switch (provider) {
            case BV -> EncryptionAlgorithm.RSASSA_PSS;
            case DTRUST -> EncryptionAlgorithm.ECDSA;
        });
        return cAdESSignatureParameters;
    }

    private static SignatureAlgorithm signatureAlgorithm(Provider provider) {
        return switch (provider) {
            case BV -> SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1;
            case DTRUST -> SignatureAlgorithm.ECDSA_SHA256;
        };
    }

    private String prompt(String toDisplay) {
        System.out.println(toDisplay);
        return new Scanner(System.in).nextLine().trim();
    }

}
