package br.api.universum.identity.shared.exception;

/** Indicates a generic business rule violation. */
public class BusinessException extends RuntimeException {

    public BusinessException(String message) {
        super(message);
    }
}
