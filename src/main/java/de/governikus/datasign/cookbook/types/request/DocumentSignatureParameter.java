package de.governikus.datasign.cookbook.types.request;

import de.governikus.datasign.cookbook.types.HashAlgorithm;
import de.governikus.datasign.cookbook.types.SignatureFormat;
import de.governikus.datasign.cookbook.types.SignatureLevel;
import de.governikus.datasign.cookbook.types.SignatureNiveau;
import de.governikus.datasign.cookbook.types.SignaturePackaging;
import de.governikus.datasign.cookbook.types.SignatureSerialization;

public record DocumentSignatureParameter(SignatureNiveau signatureNiveau,
                                         SignatureLevel signatureLevel,
                                         HashAlgorithm hashAlgorithm,
                                         SignatureFormat signatureFormat,
                                         SignaturePackaging signaturePackaging,
                                         SignatureSerialization signatureSerialization) {
}
