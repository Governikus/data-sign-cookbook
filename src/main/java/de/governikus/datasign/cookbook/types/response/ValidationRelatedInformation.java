package de.governikus.datasign.cookbook.types.response;

import java.util.List;

public record ValidationRelatedInformation(List<byte[]> certificateChain, List<byte[]> ocsp, List<byte[]> crl) {
}
