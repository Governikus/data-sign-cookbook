package de.governikus.datasign.cookbook.types.request;

public record VisualParameter(Integer pageNumber, RelativeCoordinate relativeCoordinates, Float relativeWidth,
                              Float relativeHeight, ModifyVisualRepresentation modifyVisualRepresentation) {

    public record RelativeCoordinate(Float x, Float y) {}

    public record ModifyVisualRepresentation(Boolean showImage,
                                             Boolean onlyShowImage,
                                             byte[] image,
                                             String signerName,
                                             String organization,
                                             String organizationUnit,
                                             String role,
                                             String hintText,
                                             String legalExtension,
                                             Boolean showBorder) {}
}
