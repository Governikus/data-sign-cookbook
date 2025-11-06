package de.governikus.datasign.cookbook.cades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.*;
import de.governikus.datasign.cookbook.types.request.*;
import de.governikus.datasign.cookbook.types.response.AvailableSeals;
import de.governikus.datasign.cookbook.types.response.Certificate;
import de.governikus.datasign.cookbook.types.response.Timestamps;
import de.governikus.datasign.cookbook.types.response.ToBeSignedSealTransaction;
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

import java.io.FileInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.UUID;

import static de.governikus.datasign.cookbook.util.AccessTokenUtil.retrieveAccessToken;

/**
 * Example for CAdES to-be-signed based sealing. This is more low level than sealing documents.
 */
public class SealToBeSignedExample extends AbstractExample {

    public static void main(String[] args) throws Exception {
        new SealToBeSignedExample().runExample();
    }

    public void runExample() throws Exception {
        props.load(new FileInputStream("cookbook.properties"));
        System.out.println("Running example with properties = " + props.getProperty("url"));

        var accessToken = retrieveAccessToken(props);

        var provider = SealProvider.valueOf(props.getProperty("example.sealProvider"));

        var timestampProvider = props.getProperty("example.timestampProvider");

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

        // calculate the DTBS from the unsigned document
        var unsignedDocument = new InMemoryDocument(new FileInputStream("sample.docx"));

        var cAdESService = DSSFactory.cAdESService();
        var signatureParameter = signatureParameters(provider, certificate.certificate());
        var dtbs = cAdESService.getDataToSign(unsignedDocument, signatureParameter);

        // POST /seal/to-be-signed/transactions
        var toBeSignedId = UUID.randomUUID();
        var transaction = send(
                POST("/seal/to-be-signed/transactions",
                        new SealToBeSignedTransactionRequest(
                                sealId,
                                new ToBeSignedSignatureParameter(SignatureNiveau.QUALIFIED, HashAlgorithm.SHA_256),
                                List.of(new ToBeSigned(toBeSignedId, dtbs.getBytes(), "sample.pdf"))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                ToBeSignedSealTransaction.class);

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

        // use the signature value and timestamp to generate a detached signature
        cAdESService.setTspSource(new DSSFactory.DataSignTspSource(timestamp.timestampToken()));
        var signedDocument = cAdESService.signDocument(unsignedDocument, signatureParameter,
                new SignatureValue(signatureAlgorithm(provider), signatureValue.signatureValue()));
        var detachedSignature = DSSUtils.toCMSSignedData(signedDocument).getEncoded();

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(unsignedDocument, signedDocument).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(detachedSignature, "sample_sealed.docx.p7s");
        System.out.println("sample.docx is now sealed and the detached signature is written to disk as sample_sealed.docx.p7s");
    }

    private static CAdESSignatureParameters signatureParameters(SealProvider provider, byte[] signingCertificate) throws Exception {
        var cAdESSignatureParameters = new CAdESSignatureParameters();
        cAdESSignatureParameters.setSignatureLevel(eu.europa.esig.dss.enumerations.SignatureLevel.CAdES_BASELINE_LT);
        cAdESSignatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        cAdESSignatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        cAdESSignatureParameters.setSigningCertificate(new CertificateToken(toX509Certificate(signingCertificate)));
        // leave #setEncryptionAlgorithm here after #setSigningCertificate
        cAdESSignatureParameters.setEncryptionAlgorithm(switch (provider) {
            case BV -> EncryptionAlgorithm.RSASSA_PSS;
            case DTRUST -> EncryptionAlgorithm.ECDSA;
            case SMARTCARDS -> EncryptionAlgorithm.ECDSA;
        });
        return cAdESSignatureParameters;
    }

    private static SignatureAlgorithm signatureAlgorithm(SealProvider provider) {
        return switch (provider) {
            case BV -> SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1;
            case DTRUST -> SignatureAlgorithm.ECDSA_SHA256;
            case SMARTCARDS -> SignatureAlgorithm.ECDSA_SHA256;
        };
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
