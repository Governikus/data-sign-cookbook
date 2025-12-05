package de.governikus.datasign.cookbook.types.response;

import java.util.List;
import java.util.UUID;

public record DocumentHashSealTransaction(UUID id, List<CMSSignedData> results) {
}
