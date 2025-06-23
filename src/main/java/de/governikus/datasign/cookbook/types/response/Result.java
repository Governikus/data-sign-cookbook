package de.governikus.datasign.cookbook.types.response;

import java.net.URI;
import java.util.UUID;

public record Result(UUID documentId, URI href) {
}
