package de.governikus.datasign.cookbook.types.request;

import java.util.List;

public record ToBeSealedTransactionRequest(String sealId, SignatureParameter signatureParameter,
                                           List<ToBeSigned> toBeSigned) {
}
