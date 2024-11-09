package appsecurity.common.exception;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MissingRequestCookieException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@RestControllerAdvice
@RequiredArgsConstructor
public class CommonExceptionController {

    @ExceptionHandler({
            BindException.class,
            IllegalStateException.class,
            IllegalArgumentException.class,
            MissingRequestCookieException.class
    })
    public ResponseEntity<ErrorResponse> handleBadRequest(Exception e) {
        if (e instanceof BindException be) {
            FieldError error = be.getFieldError();
            return ResponseEntity.status(BAD_REQUEST)
                    .body(ErrorResponse.builder()
                            .message(error.getField() + " " + error.getDefaultMessage())
                            .build());
        }
        return ResponseEntity.status(BAD_REQUEST)
                .body(ErrorResponse.builder()
                        .message(e.getMessage())
                        .build());
    }

    @ExceptionHandler({NotFoundException.class})
    public ResponseEntity<ErrorResponse> handleNotFound(NotFoundException e) {
        return ResponseEntity.status(e.getStatus())
                .body(ErrorResponse.builder()
                        .message(e.getMessage())
                        .build());
    }

    @ExceptionHandler(CustomException.class)
    public ResponseEntity<ErrorResponse> handleCustomException(CustomException e) {
        return ResponseEntity
                .status(e.getStatus())
                .body(ErrorResponse.builder()
                        .message(e.getMessage())
                        .build());
    }
}
