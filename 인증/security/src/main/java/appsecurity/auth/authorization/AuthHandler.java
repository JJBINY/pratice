package appsecurity.auth.authorization;

import jakarta.servlet.http.HttpServletRequest;

@Deprecated
public interface AuthHandler {
    void handle(HttpServletRequest request);
}
