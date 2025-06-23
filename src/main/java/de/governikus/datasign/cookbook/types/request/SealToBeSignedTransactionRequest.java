package de.governikus.datasign.cookbook.types.request;

import java.util.List;

public record SealToBeSignedTransactionRequest(String sealId, ToBeSignedSignatureParameter signatureParameter,
                                               List<ToBeSigned> toBeSigned) {
}
