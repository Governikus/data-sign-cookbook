package de.governikus.datasign.cookbook.types.response;

import de.governikus.datasign.cookbook.types.SignatureNiveau;

public record Certificate(byte[] certificate, SignatureNiveau signatureNiveau) {
}
