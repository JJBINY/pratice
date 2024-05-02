package app.exception.type;

import org.springframework.http.HttpStatus;

public class UnauthenticatedException extends CustomException{
    private static final String MESSAGE = "인증에 실패하였습니다.";
    public UnauthenticatedException() {
        super(MESSAGE);
    }

    public UnauthenticatedException(String message) {
        super(message);
    }

    @Override
    public HttpStatus getStatus() {
        return HttpStatus.UNAUTHORIZED;
    }
}
