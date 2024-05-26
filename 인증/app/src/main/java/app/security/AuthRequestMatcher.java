package app.security;

import app.security.authorization.Role;
import org.springframework.http.HttpMethod;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.Objects.isNull;


public final class AuthRequestMatcher {

    private final HttpMethod method;
    private final String pathPattern;
    private final PathMatcher pathMatcher;
    private final List<Role> authorities;

    private AuthRequestMatcher(HttpMethod method, String pathPattern, PathMatcher pathMatcher, List<Role> authorities) {
        this.method = method;
        this.pathPattern = pathPattern;
        this.pathMatcher = isNull(pathMatcher) ? new AntPathMatcher() : pathMatcher;
        this.authorities = isNull(authorities) ? emptyList() : authorities;
    }

    public static Builder builder() {
        return new Builder();
    }

    public boolean matches(String method, String uri, String authority) {
        boolean hasAuthority = authorities.stream().anyMatch(authority::equals);
        return matches(method, uri) && hasAuthority;
    }

    public boolean matches(String method, String uri) {
        boolean hasMethod = this.method == null ? true : this.method.matches(method);
        boolean hasPath = pathMatcher.match(pathPattern, uri);
        return hasMethod && hasPath;
    }

    public List<Role> getAuthorities() {
        return authorities;
    }

    public static class Builder {
        private AuthInterceptor.Builder parentBuilder;
        private HttpMethod method;
        private String pathPattern;
        private PathMatcher pathMatcher;
        private List<Role> authorities;

        private Builder() {
        }

        public Builder parentBuilder(AuthInterceptor.Builder parentBuilder) {
            this.parentBuilder = parentBuilder;
            return this;
        }

        public Builder method(HttpMethod method) {
            this.method = method;
            return this;
        }

        public Builder pathPattern(String pathPattern) {
            this.pathPattern = pathPattern;
            return this;
        }

        public Builder pathMatcher(PathMatcher pathMatcher) {
            this.pathMatcher = Builder.this.pathMatcher;
            return this;
        }

        public AuthInterceptor.Builder hasRole(Role role) {
            this.authorities = List.of(role);
            return parentBuilder;
        }

        public AuthInterceptor.Builder hasRoles(List<Role> roles) {
            this.authorities = roles;
            return parentBuilder;
        }

        public AuthInterceptor.Builder include(String pathPattern) {
            return include(null, pathPattern);
        }

        public AuthInterceptor.Builder include(HttpMethod method, String pathPattern) {
            parentBuilder.include(method, pathPattern);
            return parentBuilder;
        }

        public AuthRequestMatcher build() {
            return new AuthRequestMatcher(method, pathPattern, pathMatcher, authorities);
        }
    }

}
