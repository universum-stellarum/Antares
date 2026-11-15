package br.api.universum.identity.modules.authentication.dto.response;

import java.time.Instant;
import java.util.UUID;

public record JwtKeyResponse(
        UUID keyId,
        String algorithm,
        Instant createdAt) {
}
