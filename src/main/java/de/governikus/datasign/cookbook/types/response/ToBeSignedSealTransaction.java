package de.governikus.datasign.cookbook.types.response;

import java.util.List;
import java.util.UUID;

public record ToBeSignedSealTransaction(UUID id, Results results) {

    public record Results(List<SignatureValue> values) {
    }
}
