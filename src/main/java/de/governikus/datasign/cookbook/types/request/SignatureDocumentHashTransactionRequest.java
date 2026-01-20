package de.governikus.datasign.cookbook.types.request;

import java.net.URI;
import java.util.List;
import java.util.UUID;

public record SignatureDocumentHashTransactionRequest(String userId, UUID certificateId,
                                                      DocumentSignatureParameter signatureParameter,
                                                      URI redirectAfterPageVisitUrl,
                                                      Boolean confirmsIdentity, String timestampProvider,
                                                      List<DocumentHash> documentHashes) {
}
