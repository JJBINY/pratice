package app.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import static org.apache.commons.lang3.StringUtils.substringAfter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationInterceptor implements HandlerInterceptor {
    private final JwtConfigProps jwtConfigProps;
    private final Jwt jwt;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String AuthHeader = request.getHeader(jwtConfigProps.getHeader());
        String token = substringAfter(AuthHeader, jwtConfigProps.scheme).trim();
        Jwt.Claims claims = jwt.verify(token);
        request.setAttribute("role", claims.role());
        return true;
    }
}
