package de.governikus.datasign.cookbook.types.response;

import java.util.UUID;

public record CMSSignedData(UUID id,  byte[] cmsSignedData) {
}
