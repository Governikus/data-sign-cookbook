package de.governikus.datasign.cookbook.jades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.HashAlgorithm;
import de.governikus.datasign.cookbook.types.SealProvider;
import de.governikus.datasign.cookbook.types.SignatureAlgorithm;
import de.governikus.datasign.cookbook.types.SignatureNiveau;
import de.governikus.datasign.cookbook.types.request.SealToBeSignedTransactionRequest;
import de.governikus.datasign.cookbook.types.request.ToBeSigned;
import de.governikus.datasign.cookbook.types.request.ToBeSignedSignatureParameter;
import de.governikus.datasign.cookbook.types.response.AvailableSeals;
import de.governikus.datasign.cookbook.types.response.Certificate;
import de.governikus.datasign.cookbook.types.response.ToBeSignedSealTransaction;
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
import java.util.UUID;

import static de.governikus.datasign.cookbook.util.AccessTokenUtil.retrieveAccessToken;

/**
 * Example for JAdES to-be-signed based sealing. This is more low level than sealing documents.
 */
public class SealToBeSignedExample extends AbstractExample {

    public static void main(String[] args) throws Exception {
        new SealToBeSignedExample().runExample();
    }

    public void runExample() throws Exception {
        props.load(new FileInputStream("cookbook.properties"));
        System.out.println("Running example with properties = " + props);

        var accessToken = retrieveAccessToken(props);

        var provider = SealProvider.valueOf(props.getProperty("example.sealProvider"));

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

        // POST /seal/to-be-signed/transactions
        var toBeSignedId = UUID.randomUUID();
        var transaction = send(
                POST("/seal/to-be-signed/transactions",
                        new SealToBeSignedTransactionRequest(
                                sealId,
                                new ToBeSignedSignatureParameter(SignatureNiveau.QUALIFIED, hashAlgorithm, signatureAlgorithm),
                                List.of(new ToBeSigned(toBeSignedId, dtbs.getBytes(), "sample.pdf"))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                ToBeSignedSealTransaction.class);

        var signatureValue = transaction.results().values().stream()
                .filter(v -> v.id().equals(toBeSignedId)).findFirst().orElseThrow();

        // use the signature value to generate a JWS signature
        var signedDocument = jAdESService.signDocument(unsignedDocument, signatureParameter,
                new SignatureValue(mapSignatureAlgorithm(signatureAlgorithm), signatureValue.signatureValue()));

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(signedDocument).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(((InMemoryDocument) signedDocument).getBytes(), "sample_sealed.json.jwt");
        System.out.println("sample.json is now sealed and the JWS signature is written to disk as sample_sealed.json.jwt");
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

}
