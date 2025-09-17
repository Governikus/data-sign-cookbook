package de.governikus.datasign.cookbook.types.response;

import java.time.Instant;

public record User(State state, Boolean needsRecurringConfirmationOfIdentity,
                   IdentificationDocument identificationDocument) {

    public record IdentificationDocument(String givenName, String familyName, Instant birthDate, String addressLine,
                                         String cityLine, String countryCodeIso2, Instant expiresOn) {

    }

    public enum State {
        NOT_REGISTERED,
        NOT_READY,
        READY
    }
}
