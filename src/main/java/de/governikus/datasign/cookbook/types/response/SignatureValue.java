package de.governikus.datasign.cookbook.types.response;

import java.util.UUID;

public record SignatureValue(UUID id, byte[] signatureValue) {
}
