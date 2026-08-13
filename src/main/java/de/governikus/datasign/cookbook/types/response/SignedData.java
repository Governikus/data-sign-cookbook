package de.governikus.datasign.cookbook.types.response;

import java.util.UUID;

public record SignedData(UUID id, byte[] signedData) {
}
