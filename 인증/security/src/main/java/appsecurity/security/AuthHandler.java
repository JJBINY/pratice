package appsecurity.security;

import jakarta.servlet.http.HttpServletRequest;

public interface AuthHandler {
    void handle(HttpServletRequest request);
}
