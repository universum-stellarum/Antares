package br.api.universum.identity.modules.user.exception;

import br.api.universum.identity.shared.exception.ResourceNotFoundException;

/** Indicates that the requested user does not exist. */
public class UserNotFoundException extends ResourceNotFoundException {

    public UserNotFoundException() {
        super("User not found.");
    }
}
