package de.governikus.datasign.cookbook.types.request;

import de.governikus.datasign.cookbook.types.EIDASType;

public record VisualRepresentationPreviewRequest(EIDASType type, Boolean showImage, Boolean onlyShowImage, byte[] image,
                                                 String signerName, String organization, String organizationUnit,
                                                 String role, String hintText, String legalExtension,
                                                 Boolean showBorder) {
}
