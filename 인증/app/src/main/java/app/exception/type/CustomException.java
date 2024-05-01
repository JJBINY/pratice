package app.exception.type;

import org.springframework.http.HttpStatus;

public abstract class CustomException extends RuntimeException {
    public CustomException() {
    }

    public CustomException(String message) {
        super(message);
    }

    public abstract HttpStatus getStatus();
}
