package de.governikus.datasign.cookbook.types.response;

import java.util.List;
import java.util.UUID;

public record ToBeSealedTransaction(UUID id, Results results) {

    public record Results(List<SignatureValueWithTimestamp> values, ValidationRelatedInformation validationRelatedInformation) {
    }
}
