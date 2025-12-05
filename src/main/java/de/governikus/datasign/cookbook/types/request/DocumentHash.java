package de.governikus.datasign.cookbook.types.request;

import java.util.UUID;

public record DocumentHash(UUID id, byte[] documentHash) {
}
