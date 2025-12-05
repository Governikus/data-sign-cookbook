package de.governikus.datasign.cookbook.types.request;

import java.util.List;

public record SealDocumentHashTransactionRequest(String sealId, DocumentSignatureParameter signatureParameter,
                                                 List<DocumentHash> documentHashes, String timestampProvider) {
}
