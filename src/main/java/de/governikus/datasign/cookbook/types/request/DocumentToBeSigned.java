package de.governikus.datasign.cookbook.types.request;

import java.util.UUID;

public record DocumentToBeSigned(UUID documentId, UUID revisionId, VisualParameter visualParameter) {
}
