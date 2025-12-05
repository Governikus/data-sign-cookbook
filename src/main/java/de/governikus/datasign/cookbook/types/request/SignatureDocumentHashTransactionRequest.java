package de.governikus.datasign.cookbook.types.request;

import java.net.URI;
import java.util.List;

public record SignatureDocumentHashTransactionRequest(String userId, DocumentSignatureParameter signatureParameter,
                                                      URI redirectAfterPageVisitUrl,
                                                      Boolean confirmsIdentity,
                                                      List<DocumentHash> documentHashes) {
}
