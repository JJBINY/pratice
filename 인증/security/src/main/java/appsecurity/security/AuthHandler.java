package appsecurity.security;

import jakarta.servlet.http.HttpServletRequest;

@Deprecated
public interface AuthHandler {
    void handle(HttpServletRequest request);
}
