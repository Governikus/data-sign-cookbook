package de.governikus.datasign.cookbook;

import de.governikus.datasign.cookbook.types.HashAlgorithm;
import de.governikus.datasign.cookbook.types.Provider;
import de.governikus.datasign.cookbook.types.SignatureLevel;
import de.governikus.datasign.cookbook.types.SignatureNiveau;
import de.governikus.datasign.cookbook.types.request.SignatureParameter;
import de.governikus.datasign.cookbook.types.request.ToBeSealedTransactionRequest;
import de.governikus.datasign.cookbook.types.request.ToBeSigned;
import de.governikus.datasign.cookbook.types.response.AvailableSeals;
import de.governikus.datasign.cookbook.types.response.Certificate;
import de.governikus.datasign.cookbook.types.response.ToBeSealedTransaction;
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
import java.util.List;
import java.util.Scanner;
import java.util.UUID;

import static de.governikus.datasign.cookbook.util.AccessTokenUtil.retrieveAccessToken;

public class SealToBeSignedExample extends AbstractExample {

    public static void main(String[] args) throws Exception {
        new SealToBeSignedExample().runExample();
    }

    public void runExample() throws Exception {
        props.load(new FileInputStream("cookbook.properties"));
        System.out.println("Running example with properties = " + props.getProperty("url"));

        var accessToken = retrieveAccessToken(props);

        var provider = Provider.valueOf(props.getProperty("example.provider"));

        // GET /seals
        var availableSeals = send(
                GET("/seals")
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                AvailableSeals.class);

        // use these to discover which seals are available and pick one sealId
        System.out.println("availableSeals = " + availableSeals);

        // here we use the sealId from our cookbook.properties file, make sure the seal is available
        var sealId = props.getProperty("example.sealId");

        // GET /seals/{sealId}/certificates
        var certificate = send(
                GET("/seals/%s/certificates".formatted(URLEncoder.encode(sealId, StandardCharsets.UTF_8)))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                Certificate.class);

        var unsignedDocument = new InMemoryDocument(new FileInputStream("sample.pdf"));

        var padesWithExternalCMSService = DSSFactory.padesWithExternalCMSService();
        var signatureParameter = signatureParameter(provider, certificate.certificate());
        var documentDigest = padesWithExternalCMSService.getMessageDigest(unsignedDocument, signatureParameter);

        var externalCMSService = DSSFactory.externalCMSService();
        var dtbs = externalCMSService.getDataToSign(documentDigest, signatureParameter);

        // POST /seal/to-be-signed/transactions
        var toBeSignedId = UUID.randomUUID();
        var transaction = send(
                POST("/seal/to-be-signed/transactions",
                        new ToBeSealedTransactionRequest(
                                sealId,
                                new SignatureParameter(SignatureNiveau.QUALIFIED, SignatureLevel.B_LT, HashAlgorithm.SHA_256),
                                List.of(new ToBeSigned(toBeSignedId, dtbs.getBytes(), "sample.pdf"))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                ToBeSealedTransaction.class);

        var signatureValueWithTimestamp = transaction.results().values().stream()
                .filter(v -> v.id().equals(toBeSignedId)).findFirst().orElseThrow();
        var cmsSignedData = DSSFactory.externalCMSService(signatureValueWithTimestamp.timestamp())
                .signMessageDigest(documentDigest, signatureParameter, new SignatureValue(signatureParameter.getSignatureAlgorithm(), signatureValueWithTimestamp.signatureValue()));

        if (!padesWithExternalCMSService.isValidCMSSignedData(documentDigest, cmsSignedData)) {
            System.err.println("signatureValue is not coherent with document digest");
            return;
        }

        var signedDocument = padesWithExternalCMSService.signDocument(unsignedDocument, signatureParameter, cmsSignedData);

        writeToDisk(signedDocument, "sample_signed.pdf");
        System.out.println("sample.pdf is now signed and written to disk as sample_signed.pdf");
    }

    private static PAdESSignatureParameters signatureParameter(Provider provider, byte[] signingCertificate) throws Exception {
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

}
