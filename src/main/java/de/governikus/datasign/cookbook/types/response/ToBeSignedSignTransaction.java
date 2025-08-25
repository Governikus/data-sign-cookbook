package de.governikus.datasign.cookbook.types.response;

import java.net.URI;
import java.util.List;
import java.util.UUID;

public record ToBeSignedSignTransaction(UUID id, State state, URI pageVisitUrl, String tanSendTo, Results results) {

    public enum State {
        FINISHED, TAN_REQUIRED, PAGE_VISIT_REQUIRED,
    }

    public record Results(List<SignatureValue> values) {
    }
}
