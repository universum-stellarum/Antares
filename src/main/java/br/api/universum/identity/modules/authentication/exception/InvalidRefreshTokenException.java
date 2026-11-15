package br.api.universum.identity.modules.authentication.exception;

import br.api.universum.identity.shared.exception.BusinessException;

/** Indicates that the given refresh token is invalid, already revoked, or expired. */
public class InvalidRefreshTokenException extends BusinessException {

    public InvalidRefreshTokenException() {
        super("Refresh token is invalid, revoked, or expired.");
    }
}
