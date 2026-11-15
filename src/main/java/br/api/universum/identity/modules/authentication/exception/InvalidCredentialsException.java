package br.api.universum.identity.modules.authentication.exception;

import br.api.universum.identity.shared.exception.BusinessException;

/** Indicates that the email or password given at login is invalid. */
public class InvalidCredentialsException extends BusinessException {

    public InvalidCredentialsException() {
        super("Invalid credentials.");
    }
}
