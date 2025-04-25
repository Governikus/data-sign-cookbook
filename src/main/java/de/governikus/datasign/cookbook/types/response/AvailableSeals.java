package de.governikus.datasign.cookbook.types.response;

import java.util.List;

public record AvailableSeals(List<Seal> seals) {

    public record Seal(String sealId, String organization, String organizationUnit, String validUntil, String error) {
    }
}
