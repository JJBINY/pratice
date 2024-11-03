package appsecurity.common.exception;

public abstract class CustomException extends RuntimeException implements CustomExceptionType {
    public CustomException() {
    }

    public CustomException(String message) {
        super(message);
    }
}
