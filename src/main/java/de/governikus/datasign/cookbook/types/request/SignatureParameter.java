package de.governikus.datasign.cookbook.types.request;

import de.governikus.datasign.cookbook.types.HashAlgorithm;
import de.governikus.datasign.cookbook.types.SignatureLevel;
import de.governikus.datasign.cookbook.types.SignatureNiveau;

public record SignatureParameter(SignatureNiveau signatureNiveau, SignatureLevel signatureLevel,
                                 HashAlgorithm hashAlgorithm) {
}
