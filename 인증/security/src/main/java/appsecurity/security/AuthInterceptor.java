package appsecurity.security;

import appsecurity.security.authorization.Role;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
public class AuthInterceptor implements HandlerInterceptor {

    private final AuthHandler authenticationHandler;
    private final AuthHandler authorizationHandler;
    private final List<AuthRequestMatcher> includeMatchers;
    private final List<AuthRequestMatcher> excludeMatchers;
    private final boolean anyMatch;


    public static Builder builder(AuthHandler authenticationHandler, AuthHandler authorizationHandler) {
        return new Builder(authenticationHandler, authorizationHandler);
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String method = request.getMethod();
        String uri = request.getRequestURI();

        if (excludeMatchers.stream().anyMatch(matcher
                -> matcher.matches(method, uri))) {
            return true;
        }
        List<AuthRequestMatcher> matchers = includeMatchers.stream().filter(matcher
                -> matcher.matches(method, uri)).toList();
        if (!matchers.isEmpty()) {
            authenticationHandler.handle(request);
            List<Role> roles = matchers.stream().map(AuthRequestMatcher::getAuthorities).flatMap(List::stream).distinct().toList();
            if (!roles.isEmpty()) {
                request.setAttribute("roles", roles);
                authorizationHandler.handle(request);
            }
            return true;
        }

        if (anyMatch) {
            authenticationHandler.handle(request);
            return true;
        }

        return false;
    }


    public static class Builder {
        private AuthHandler authenticationHandler;
        private AuthHandler authorizationHandler;
        private List<AuthRequestMatcher.Builder> includeMatcherBuilders = new ArrayList<>();
        private List<AuthRequestMatcher> excludeMatchers = new ArrayList<>();
        private boolean anyMatch;

        protected Builder(AuthHandler authenticationHandler, AuthHandler authorizationHandler) {
            this.authenticationHandler = authenticationHandler;
            this.authorizationHandler = authorizationHandler;
        }


        public Builder anyMatch() {
            this.anyMatch = true;
            return this;
        }

        public AuthRequestMatcher.Builder include(String pathPattern) {
            return include(null, pathPattern);
        }

        public AuthRequestMatcher.Builder include(HttpMethod method, String pathPattern) {
            AuthRequestMatcher.Builder childBuilder = AuthRequestMatcher.builder()
                    .parentBuilder(this)
                    .method(method)
                    .pathPattern(pathPattern);
            includeMatcherBuilders.add(childBuilder);
            return childBuilder;
        }

        public Builder exclude(String pathPattern) {
            return exclude(null, pathPattern);
        }

        public Builder exclude(HttpMethod method, String pathPattern) {
            excludeMatchers.add(AuthRequestMatcher.builder()
                    .method(method)
                    .pathPattern(pathPattern)
                    .build());
            return this;
        }

        public AuthInterceptor build() {
            return new AuthInterceptor(
                    authenticationHandler,
                    authorizationHandler,
                    includeMatcherBuilders.stream().map(AuthRequestMatcher.Builder::build).toList(),
                    excludeMatchers,
                    anyMatch
            );
        }
    }

}
