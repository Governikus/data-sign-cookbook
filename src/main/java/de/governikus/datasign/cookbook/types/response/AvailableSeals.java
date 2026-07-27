package de.governikus.datasign.cookbook.types.response;

import de.governikus.datasign.cookbook.types.HashAlgorithm;
import de.governikus.datasign.cookbook.types.SignatureAlgorithm;
import de.governikus.datasign.cookbook.types.SignatureNiveau;

import java.util.List;

public record AvailableSeals(List<Seal> seals) {

    public record Seal(String sealId, String organization, String organizationUnit, String validUntil,
                       SignatureNiveau signatureNiveau, List<HashAlgorithm> hashAlgorithms,
                       List<SignatureAlgorithm> signatureAlgorithms, String error) {
    }
}
