package appsecurity.common.exception;

import org.springframework.http.HttpStatus;

public class AlreadyExistsException extends CustomException{
    private static final String MESSAGE = "자원이 이미 존재합니다.";
    public AlreadyExistsException() {
        super(MESSAGE);
    }

    public AlreadyExistsException(String message) {
        super(message);
    }

    @Override
    public HttpStatus getStatus() {
        return HttpStatus.CONFLICT;
    }
}
