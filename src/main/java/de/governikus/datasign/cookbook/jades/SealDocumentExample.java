package de.governikus.datasign.cookbook.jades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.HashAlgorithm;
import de.governikus.datasign.cookbook.types.SealProvider;
import de.governikus.datasign.cookbook.types.SignatureFormat;
import de.governikus.datasign.cookbook.types.SignatureLevel;
import de.governikus.datasign.cookbook.types.SignatureNiveau;
import de.governikus.datasign.cookbook.types.SignaturePackaging;
import de.governikus.datasign.cookbook.types.SignatureSerialization;
import de.governikus.datasign.cookbook.types.request.DocumentSignatureParameter;
import de.governikus.datasign.cookbook.types.request.DocumentToBeSigned;
import de.governikus.datasign.cookbook.types.request.SealDocumentTransactionRequest;
import de.governikus.datasign.cookbook.types.response.AvailableSeals;
import de.governikus.datasign.cookbook.types.response.DocumentSealTransaction;
import de.governikus.datasign.cookbook.types.response.UploadedDocument;
import de.governikus.datasign.cookbook.util.DSSFactory;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.io.FileInputStream;
import java.util.List;

import static de.governikus.datasign.cookbook.util.AccessTokenUtil.retrieveAccessToken;

/**
 * Example for document sealing.
 */
public class SealDocumentExample extends AbstractExample {

    public static void main(String[] args) throws Exception {
        new SealDocumentExample().runExample();
    }

    public void runExample() throws Exception {
        props.load(new FileInputStream("cookbook.properties"));
        System.out.println("Running example with properties = " + props);

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

        // POST /documents
        var uploadedDocument = send(POST("/documents", new String(new FileInputStream("sample.json").readAllBytes()))
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                UploadedDocument.class);

        // POST /seal/document/transactions
        var transaction = send(
                POST("/seal/document/transactions",
                        new SealDocumentTransactionRequest(
                                sealId,
                                new DocumentSignatureParameter(SignatureNiveau.QUALIFIED, SignatureLevel.B_LT,
                                        HashAlgorithm.SHA_256, SignatureFormat.JADES, SignaturePackaging.ENVELOPING, SignatureSerialization.JWS_JSON),
                                List.of(new DocumentToBeSigned(uploadedDocument.documentId(), null, null)),
                                timestampProvider))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentSealTransaction.class);

        var signedDocument = transaction.results().stream().filter(r ->
                r.documentId().equals(uploadedDocument.documentId())).findFirst().orElseThrow();
        var signedJWS = signedDocument.signedDocument();

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(new InMemoryDocument(new FileInputStream("sample.json")),
                new InMemoryDocument(signedJWS)).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(signedJWS, "sample_sealed.json");
        System.out.println("sample.json is now sealed and the signature is written to disk as sample_sealed.json");
    }

}
