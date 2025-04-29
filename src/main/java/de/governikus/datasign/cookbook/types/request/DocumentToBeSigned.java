package de.governikus.datasign.cookbook.types.request;

import java.util.UUID;

public record DocumentToBeSigned(UUID documentId, UUID revisionId, SignatureFormat signatureFormat,
                                 SignaturePackaging signaturePackaging, VisualParameter visualParameter) {

    public enum SignatureFormat {
        PADES
    }

    public enum SignaturePackaging {
        ENVELOPED
    }
}
