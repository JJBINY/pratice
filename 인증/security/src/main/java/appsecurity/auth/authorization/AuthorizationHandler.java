package appsecurity.auth.authorization;

import appsecurity.exception.type.UnauthorizedException;
import appsecurity.auth.Role;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Deprecated
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
