package de.governikus.datasign.cookbook.cades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.*;
import de.governikus.datasign.cookbook.types.request.*;
import de.governikus.datasign.cookbook.types.response.AvailableSeals;
import de.governikus.datasign.cookbook.types.response.DocumentHashSealTransaction;
import de.governikus.datasign.cookbook.types.response.DocumentSealTransaction;
import de.governikus.datasign.cookbook.types.response.UploadedDocument;
import de.governikus.datasign.cookbook.util.DSSFactory;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.io.FileInputStream;
import java.security.MessageDigest;
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
        var documentHash = MessageDigest.getInstance("SHA-256").digest(new FileInputStream("sample.docx").readAllBytes());

        // POST /seal/document-hash/transactions
        var documentHashId = UUID.randomUUID();
        var transaction = send(
                POST("/seal/document-hash/transactions",
                        new SealDocumentHashTransactionRequest(
                                sealId,
                                new DocumentSignatureParameter(SignatureNiveau.QUALIFIED, SignatureLevel.B_LT,
                                        HashAlgorithm.SHA_256, SignatureFormat.CADES, SignaturePackaging.DETACHED),
                                List.of(new DocumentHash(documentHashId, documentHash)), timestampProvider))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentHashSealTransaction.class);

        var cmsSignedData = transaction.results().stream().filter(r ->
                r.id().equals(documentHashId)).findFirst().orElseThrow();

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(new InMemoryDocument(new FileInputStream("sample.docx")),
                new InMemoryDocument(cmsSignedData.cmsSignedData())).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(cmsSignedData.cmsSignedData(), "sample_sealed.docx.p7s");
        System.out.println("sample.docx is now sealed and the signature is written to disk as sample_sealed.docx.p7s");
    }

}
