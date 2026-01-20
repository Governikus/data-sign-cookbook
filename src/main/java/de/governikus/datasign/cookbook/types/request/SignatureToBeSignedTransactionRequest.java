package de.governikus.datasign.cookbook.types.request;

import java.net.URI;
import java.util.List;
import java.util.UUID;

public record SignatureToBeSignedTransactionRequest(String userId, UUID certificateId,
                                                    ToBeSignedSignatureParameter signatureParameter,
                                                    URI redirectAfterPageVisitUrl,
                                                    List<ToBeSigned> toBeSigned) {
}
