package app.security.authorization;

import app.exception.type.UnauthorizedException;
import app.security.AuthHandler;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class AuthorizationHandler implements AuthHandler {

    @Override
    public void handle(HttpServletRequest request) {
        List<Role> roles = (List) request.getAttribute("roles");
        Role userRole = (Role) request.getAttribute("role");
        if (!roles.stream().anyMatch(userRole::equals)) {
            throw new UnauthorizedException();
        }
    }
}
