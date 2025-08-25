package de.governikus.datasign.cookbook.types.request;

import de.governikus.datasign.cookbook.types.HashAlgorithm;

import java.util.UUID;

public record Digest(UUID id, HashAlgorithm hashAlgorithm, byte[] digest) {
}
