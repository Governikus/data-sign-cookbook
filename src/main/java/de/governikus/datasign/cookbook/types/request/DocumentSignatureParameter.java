package de.governikus.datasign.cookbook.types.request;

import de.governikus.datasign.cookbook.types.*;

public record DocumentSignatureParameter(SignatureNiveau signatureNiveau, SignatureLevel signatureLevel,
                                         HashAlgorithm hashAlgorithm, SignatureFormat signatureFormat, SignaturePackaging signaturePackaging) {
}
