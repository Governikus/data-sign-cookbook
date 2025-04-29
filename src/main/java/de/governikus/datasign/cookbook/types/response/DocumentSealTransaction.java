package de.governikus.datasign.cookbook.types.response;

import java.util.List;
import java.util.UUID;

public record DocumentSealTransaction(UUID id, List<DocumentRevision> results) {
}
