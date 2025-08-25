package de.governikus.datasign.cookbook.types.request;

import java.util.List;

public record TimestampRequest(String timestampProvider, List<Digest> digests) {
}
