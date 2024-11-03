package appsecurity.auth.handler;

import appsecurity.auth.config.AuthProps;
import appsecurity.auth.exception.UnauthorizedException;
import appsecurity.common.exception.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static org.apache.commons.lang3.StringUtils.SPACE;
import static org.apache.commons.lang3.StringUtils.joinWith;

@Slf4j
@Component
@RequiredArgsConstructor
public class Auth403Handler implements AccessDeniedHandler {
    static final ErrorResponse errorResponse = ErrorResponse.builder()
            .message(UnauthorizedException.DEFAULT_MESSAGE +"@@@@@@@@@@@@")
            .build();

    private final AuthProps authProps;
    private final ObjectMapper objectMapper;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        log.info("Auth403Handler: requestURI = {}", request.getRequestURI());
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, joinWith(SPACE, authProps.scheme, "realm=\"access to the api\""));
        objectMapper.writeValue(response.getWriter(), errorResponse);
    }
}
