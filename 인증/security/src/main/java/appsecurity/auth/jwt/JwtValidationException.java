package appsecurity.auth.jwt;

public class JwtValidationException extends Exception {
    public JwtValidationException() {
        super("유효하지 않은 토큰입니다");
    }

    public JwtValidationException(String message) {
        super(message);
    }
}
