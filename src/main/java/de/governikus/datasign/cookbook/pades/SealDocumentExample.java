package de.governikus.datasign.cookbook.pades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.HashAlgorithm;
import de.governikus.datasign.cookbook.types.Provider;
import de.governikus.datasign.cookbook.types.SignatureLevel;
import de.governikus.datasign.cookbook.types.SignatureNiveau;
import de.governikus.datasign.cookbook.types.request.*;
import de.governikus.datasign.cookbook.types.response.*;

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
                                new SignatureParameter(SignatureNiveau.QUALIFIED, SignatureLevel.B_LT, HashAlgorithm.SHA_256),
                                List.of(new DocumentToBeSigned(uploadedDocument.documentId(),
                                        null,
                                        DocumentToBeSigned.SignatureFormat.PADES,
                                        DocumentToBeSigned.SignaturePackaging.ENVELOPED,
                                        new VisualParameter(1,
                                                new VisualParameter.RelativeCoordinate(0.68f, 0.88f),
                                                0.3f, 0.1f, null, null)))))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentSealTransaction.class);

        var documentRevision = transaction.results().stream().filter(r ->
                r.documentId().equals(uploadedDocument.documentId())).findFirst().orElseThrow();

        // GET /documents/{documentId}/revisions/{revisionId}
        var documentRevisionBytes = retrieveBytes(GET(documentRevision.href().toString())
                .header("Authorization", accessToken.toAuthorizationHeader()));

        writeToDisk(documentRevisionBytes, "sample_sealed.pdf");
        System.out.println("sample.pdf is now sealed and written to disk as sample_sealed.pdf");
    }

}
