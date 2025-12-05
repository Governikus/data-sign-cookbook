package de.governikus.datasign.cookbook.pades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.*;
import de.governikus.datasign.cookbook.types.request.*;
import de.governikus.datasign.cookbook.types.response.AvailableSeals;
import de.governikus.datasign.cookbook.types.response.DocumentHashSealTransaction;
import de.governikus.datasign.cookbook.types.response.DocumentSealTransaction;
import de.governikus.datasign.cookbook.types.response.UploadedDocument;
import de.governikus.datasign.cookbook.util.DSSFactory;
import eu.europa.esig.dss.cms.CMSSignedDocument;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.spi.DSSUtils;

import java.io.FileInputStream;
import java.util.List;
import java.util.UUID;

import static de.governikus.datasign.cookbook.util.AccessTokenUtil.retrieveAccessToken;

/**
 * Example for document hash sealing.
 */
public class SealDocumentHashExample extends AbstractExample {

    public static void main(String[] args) throws Exception {
        new SealDocumentHashExample().runExample();
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

        // calculate the document hash from the unsigned document
        var unsignedDocument = new InMemoryDocument(new FileInputStream("sample.pdf"));

        var signatureParameter = signatureParameter(HashAlgorithm.SHA_256);
        var documentHash = DSSFactory.pAdESWithExternalCMSService().getMessageDigest(unsignedDocument, signatureParameter).getValue();

        // POST /seal/document-hash/transactions
        var documentHashId = UUID.randomUUID();
        var transaction = send(
                POST("/seal/document-hash/transactions",
                        new SealDocumentHashTransactionRequest(
                                sealId,
                                new DocumentSignatureParameter(SignatureNiveau.QUALIFIED, SignatureLevel.B_LT,
                                        HashAlgorithm.SHA_256, SignatureFormat.PADES, SignaturePackaging.ENVELOPED),
                                List.of(new DocumentHash(documentHashId, documentHash)), timestampProvider))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentHashSealTransaction.class);

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

        // extend signature to LT-Level
        signedDocument = DSSFactory.pAdESExtensionService().incorporateValidationData(signedDocument, null, true);

        writeToDisk(signedDocument, "sample_sealed.pdf");
        System.out.println("sample.pdf is now sealed and written to disk as sample_sealed.pdf");
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
