package de.governikus.datasign.cookbook.jades;

import de.governikus.datasign.cookbook.AbstractExample;
import de.governikus.datasign.cookbook.types.HashAlgorithm;
import de.governikus.datasign.cookbook.types.SealProvider;
import de.governikus.datasign.cookbook.types.SignatureFormat;
import de.governikus.datasign.cookbook.types.SignatureLevel;
import de.governikus.datasign.cookbook.types.SignatureNiveau;
import de.governikus.datasign.cookbook.types.SignaturePackaging;
import de.governikus.datasign.cookbook.types.SignatureSerialization;
import de.governikus.datasign.cookbook.types.request.DocumentHash;
import de.governikus.datasign.cookbook.types.request.DocumentSignatureParameter;
import de.governikus.datasign.cookbook.types.request.SealDocumentHashTransactionRequest;
import de.governikus.datasign.cookbook.types.response.AvailableSeals;
import de.governikus.datasign.cookbook.types.response.DocumentHashSealTransaction;
import de.governikus.datasign.cookbook.util.DSSFactory;
import eu.europa.esig.dss.jades.DSSJsonUtils;
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

        // calculate the document hash from the Base64 URL encoded JSON payload
        var documentHash = MessageDigest.getInstance("SHA-512").digest(
                DSSJsonUtils.toBase64Url(new FileInputStream("sample.json").readAllBytes()).getBytes());

        // POST /seal/document-hash/transactions
        var documentHashId = UUID.randomUUID();
        var transaction = send(
                POST("/seal/document-hash/transactions",
                        new SealDocumentHashTransactionRequest(
                                sealId,
                                new DocumentSignatureParameter(SignatureNiveau.QUALIFIED, SignatureLevel.B_B,
                                        HashAlgorithm.SHA_512, SignatureFormat.JADES, SignaturePackaging.DETACHED, SignatureSerialization.JWS_COMPACT),
                                List.of(new DocumentHash(documentHashId, documentHash)), null))
                        .header("provider", provider.toString())
                        .header("Authorization", accessToken.toAuthorizationHeader()),
                DocumentHashSealTransaction.class);

        var signedData = transaction.results().stream().filter(r ->
                r.id().equals(documentHashId)).findFirst().orElseThrow();

        // check if the signature is valid
        var report = DSSFactory.signedDocumentValidator(new InMemoryDocument(new FileInputStream("sample.json")),
                new InMemoryDocument(signedData.signedData())).validateDocument().getSimpleReport();
        var indication = report.getIndication(report.getFirstSignatureId()).name();
        if (indication.equals("FAILED") || indication.equals("TOTAL_FAILED") || indication.equals("NO_SIGNATURE_FOUND")) {
            System.err.println("signature is not valid");
        }

        writeToDisk(signedData.signedData(), "sample_sealed.json.jwt");
        System.out.println("sample.json is now sealed and the signature is written to disk as sample_sealed.json.jwt");
    }

}
