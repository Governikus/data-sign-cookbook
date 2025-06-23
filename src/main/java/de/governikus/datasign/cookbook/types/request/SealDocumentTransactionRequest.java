package de.governikus.datasign.cookbook.types.request;

import java.util.List;

public record SealDocumentTransactionRequest(String sealId, DocumentSignatureParameter signatureParameter,
                                            List<DocumentToBeSigned> documents) {
}
