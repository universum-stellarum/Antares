package br.api.universum.identity.modules.user.exception;

import br.api.universum.identity.shared.exception.ConflictException;

/** Indicates that the given email is already registered to another user. */
public class EmailAlreadyInUseException extends ConflictException {

    public EmailAlreadyInUseException() {
        super("Email is already in use.");
    }
}
