package de.governikus.datasign.cookbook.types.request;

import java.net.URI;
import java.util.List;

public record SignatureDocumentTransactionRequest(String userId, SignatureParameter signatureParameter,
                                                  URI redirectAfterPageVisitUrl,
                                                  List<DocumentToBeSigned> documents) {
}
