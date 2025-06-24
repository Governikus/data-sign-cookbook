package de.governikus.datasign.cookbook.cades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.*;
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

        // POST /documents
        var uploadedDocument = send(POST("/documents", new FileInputStream("sample.pdf").readAllBytes())
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                UploadedDocument.class);

        // POST /seal/document/transactions
        var transaction = send(
                POST("/seal/document/transactions",
                        new SealDocumentTransactionRequest(
                                sealId,
                                new DocumentSignatureParameter(SignatureNiveau.QUALIFIED, SignatureLevel.B_LT,
                                        HashAlgorithm.SHA_256, SignatureFormat.CADES, SignaturePackaging.ENVELOPING),
                                List.of(new DocumentToBeSigned(uploadedDocument.documentId(), null, null))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentSealTransaction.class);

        var pkcs7Signatures = transaction.results().stream().filter(r ->
                r.documentId().equals(uploadedDocument.documentId())).findFirst().orElseThrow();

        // GET /documents/{documentId}/signatures/{signatureId}
        var pkcs7SignatureBytes = retrieveBytes(GET(pkcs7Signatures.href().toString())
                .header("Authorization", accessToken.toAuthorizationHeader()));

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(new InMemoryDocument(new FileInputStream("sample.docx")),
                new InMemoryDocument(pkcs7SignatureBytes)).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(pkcs7SignatureBytes, "sample_sealed.docx.p7s");
        System.out.println("sample.pdf is now sealed and the signature is written to disk as sample_sealed.docx.p7s");
    }

}
