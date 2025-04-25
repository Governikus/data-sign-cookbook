package de.governikus.datasign.cookbook.types.response;

import java.util.UUID;

public record SignatureValueWithTimestamp(UUID id, byte[] signatureValue, byte[] timestamp) {
}
