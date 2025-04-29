package de.governikus.datasign.cookbook.types.response;

import java.net.URI;
import java.util.List;
import java.util.UUID;

public record DocumentSignTransaction(UUID id, State state, URI pageVisitUrl, String tanSendTo, List<DocumentRevision> results) {

    public enum State {
        FINISHED, TAN_REQUIRED, PAGE_VISIT_REQUIRED
    }
}
