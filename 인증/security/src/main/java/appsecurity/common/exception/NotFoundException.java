package appsecurity.common.exception;

import org.springframework.http.HttpStatus;

public class NotFoundException extends CustomException {
    private static final String MESSAGE = "자원을 찾을 수 없습니다";
    public NotFoundException() {
        super(MESSAGE);
    }

    public NotFoundException(String message) {
        super(message);
    }

    @Override
    public HttpStatus getStatus() {
        return HttpStatus.NOT_FOUND;
    }
}
