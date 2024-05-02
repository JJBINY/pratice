package app.security;

import app.exception.type.UnauthorizedException;
import app.user.Role;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Arrays;

@Component
@RequiredArgsConstructor
public class AuthorizationInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        HandlerMethod handlerMethod = (HandlerMethod) handler;
        RequireAuthority requireAuthority = handlerMethod.getMethodAnnotation(RequireAuthority.class);
        Role role = (Role) request.getAttribute("role");
        if (requireAuthority != null &&
                !Arrays.stream(requireAuthority.authorities()).anyMatch(authority -> authority == role)) {
            throw new UnauthorizedException();
        }

        return true;
    }

}
