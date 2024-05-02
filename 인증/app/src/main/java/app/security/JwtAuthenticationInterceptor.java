package app.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationInterceptor implements HandlerInterceptor {
    private final JwtConfigProps jwtConfigProps;
    private final Jwt jwt;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String token = request.getHeader(jwtConfigProps.getHeader());
        Jwt.Claims claims = jwt.verify(token);
        request.setAttribute("role", claims.role());
        return true;
    }

}
