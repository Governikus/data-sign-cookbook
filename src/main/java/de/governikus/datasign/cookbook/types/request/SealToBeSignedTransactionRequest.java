package de.governikus.datasign.cookbook.types.request;

import java.util.List;

public record SealToBeSignedTransactionRequest(String sealId, SignatureParameter signatureParameter,
                                               List<ToBeSigned> toBeSigned) {
}
