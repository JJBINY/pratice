package appsecurity.common.exception;

import org.springframework.http.HttpStatus;

public interface CustomExceptionType {
    String getMessage();
    HttpStatus getStatus();
}
