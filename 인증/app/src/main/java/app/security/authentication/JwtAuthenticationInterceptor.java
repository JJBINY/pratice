package app.security.authentication;

import app.exception.type.UnauthenticatedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.apache.commons.lang3.StringUtils.substringAfter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationInterceptor implements HandlerInterceptor {
    private final JwtConfigProps jwtConfigProps;
    private final Jwt jwt;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String AuthHeader = request.getHeader(jwtConfigProps.getHeader());
        if (isEmpty(AuthHeader)) {
            throw new UnauthenticatedException("인증이 필요한 요청입니다.");
        }
        String token = substringAfter(AuthHeader, jwtConfigProps.scheme).trim();
        Jwt.Claims claims = jwt.verify(token);
        request.setAttribute("role", claims.role());
        return true;
    }
}
