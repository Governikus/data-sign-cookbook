package de.governikus.datasign.cookbook.types.request;

public record VisualParameter(Integer pageNumber, RelativeCoordinate relativeCoordinates, Float relativeWidth,
                              Float relativeHeight, ModifyVisualRepresentation modifyVisualRepresentation,
                              byte[] replaceVisualRepresentation) {

    public record RelativeCoordinate(Float x, Float y) {}

    public record ModifyVisualRepresentation(byte[] image, Float relativeImageWidth, String text) {}
}
