package de.governikus.datasign.cookbook.types.response;

import de.governikus.datasign.cookbook.types.HashAlgorithm;

import java.util.UUID;

public record TimestampToken(UUID id, byte[] timestampToken) {
}
