package appsecurity.exception.type;

import org.springframework.http.HttpStatus;

public class UnauthenticatedException extends CustomException{
    public static final String DEFAULT_MESSAGE = "인증에 실패하였습니다.";
    public UnauthenticatedException() {
        super(DEFAULT_MESSAGE);
    }

    public UnauthenticatedException(String message) {
        super(message);
    }

    @Override
    public HttpStatus getStatus() {
        return HttpStatus.UNAUTHORIZED;
    }
}
