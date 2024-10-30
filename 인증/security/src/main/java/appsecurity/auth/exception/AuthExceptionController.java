package appsecurity.auth.exception;

import appsecurity.auth.config.AuthProps;
import appsecurity.common.exception.CustomException;
import appsecurity.common.exception.ErrorResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static org.apache.commons.lang3.StringUtils.SPACE;
import static org.apache.commons.lang3.StringUtils.joinWith;

@RestControllerAdvice
@RequiredArgsConstructor
public class AuthExceptionController {

    private final AuthProps authProps;

    @ExceptionHandler(UnauthenticatedException.class)
    public ResponseEntity<ErrorResponse> handleUnauthenticatedException(CustomException e) {

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE, joinWith(SPACE, authProps.scheme, "realm=\"access to the api\""))
                .body(ErrorResponse.builder()
                        .message(e.getMessage())
                        .build());
    }
}
