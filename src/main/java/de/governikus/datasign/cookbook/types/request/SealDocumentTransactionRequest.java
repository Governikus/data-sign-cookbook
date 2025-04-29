package de.governikus.datasign.cookbook.types.request;

import java.util.List;

public record SealDocumentTransactionRequest(String sealId, SignatureParameter signatureParameter,
                                            List<DocumentToBeSigned> documents) {
}
