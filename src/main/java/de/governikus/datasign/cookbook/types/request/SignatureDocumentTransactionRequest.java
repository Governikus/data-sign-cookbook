package de.governikus.datasign.cookbook.types.request;

import java.net.URI;
import java.util.List;

public record SignatureDocumentTransactionRequest(String userId, DocumentSignatureParameter signatureParameter,
                                                  URI redirectAfterPageVisitUrl,
                                                  Boolean confirmsIdentity,
                                                  List<DocumentToBeSigned> documents) {
}
