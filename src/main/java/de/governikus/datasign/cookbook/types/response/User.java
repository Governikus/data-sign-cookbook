package de.governikus.datasign.cookbook.types.response;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record User(State state, Boolean needsRecurringConfirmationOfIdentity,
                   IdentificationDocument identificationDocument, List<Certificate> certificates) {

    public record IdentificationDocument(String givenName, String familyName, Instant birthDate, String addressLine,
                                         String cityLine, String countryCodeIso2, Instant expiresOn) {

    }

    public record Certificate(UUID id, String displayName) {
    }

    public enum State {
        NOT_REGISTERED,
        NOT_READY,
        READY
    }
}
