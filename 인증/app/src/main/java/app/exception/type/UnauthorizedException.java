package app.exception.type;

import org.springframework.http.HttpStatus;

public class UnauthorizedException extends CustomException{
    private static final String MESSAGE = "인증에 실패하였습니다.";
    public UnauthorizedException() {
        super(MESSAGE);
    }

    public UnauthorizedException(String message) {
        super(message);
    }

    @Override
    public HttpStatus getStatus() {
        return HttpStatus.UNAUTHORIZED;
    }
}
