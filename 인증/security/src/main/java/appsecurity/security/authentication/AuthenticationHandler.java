package appsecurity.security.authentication;

import appsecurity.exception.type.UnauthenticatedException;
import appsecurity.security.AuthHandler;
import appsecurity.security.AuthProps;
import appsecurity.security.jwt.Jwt;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.apache.commons.lang3.StringUtils.substringAfter;

@Component
@RequiredArgsConstructor
public class AuthenticationHandler implements AuthHandler {
    private final AuthProps props;
    private final Jwt jwt;

    @Override
    public void handle(HttpServletRequest request) {
        String AuthHeader = request.getHeader(props.header);
        if (isEmpty(AuthHeader)) {
            throw new UnauthenticatedException("인증이 필요한 요청입니다.");
        }
        String token = substringAfter(AuthHeader, props.header).trim();
        Jwt.Claims claims = jwt.verify(token);
        request.setAttribute("role", claims.role());
    }
}
