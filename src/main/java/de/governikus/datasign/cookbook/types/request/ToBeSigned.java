package de.governikus.datasign.cookbook.types.request;

import java.util.UUID;

public record ToBeSigned(UUID id, byte[] toBeSignedData, String originsFrom) {
}
