package app.exception.type;

import org.springframework.http.HttpStatus;

public class UnauthorizedException extends CustomException{
    private static final String MESSAGE = "해당 작업에 대한 권한이 없습니다.";
    public UnauthorizedException() {
        super(MESSAGE);
    }

    public UnauthorizedException(String message) {
        super(message);
    }

    @Override
    public HttpStatus getStatus() {
        return HttpStatus.FORBIDDEN;
    }
}
