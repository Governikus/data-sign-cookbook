package de.governikus.datasign.cookbook.types.response;

import de.governikus.datasign.cookbook.types.SignatureAlgorithm;
import de.governikus.datasign.cookbook.types.SignatureNiveau;

import java.util.List;

public record Certificate(byte[] certificate, SignatureNiveau signatureNiveau,
                          List<SignatureAlgorithm> signatureAlgorithms) {
}
