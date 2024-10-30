package appsecurity.auth.handler;

import appsecurity.auth.config.AuthProps;
import appsecurity.common.exception.ErrorResponse;
import appsecurity.auth.exception.UnauthenticatedException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static org.apache.commons.lang3.StringUtils.SPACE;
import static org.apache.commons.lang3.StringUtils.joinWith;

@RequiredArgsConstructor
@Component
public class Auth401Handler implements AuthenticationEntryPoint {
    static final ErrorResponse errorResponse = ErrorResponse.builder()
            .message(UnauthenticatedException.DEFAULT_MESSAGE)
            .build();

    private final AuthProps authProps;
    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, joinWith(SPACE, authProps.scheme, "realm=\"access to the api\""));
        objectMapper.writeValue(response.getWriter(), errorResponse);
    }
}
