package app.security;

import app.security.authentication.AuthenticateUserResolver;
import app.security.authentication.AuthenticationHandler;
import app.security.authorization.AuthorizationHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

import static app.security.authorization.Role.ADMIN;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration
@RequiredArgsConstructor
public class SecurityWebMvcConfig implements WebMvcConfigurer {

    private final AuthenticationHandler authenticationHandler;
    private final AuthorizationHandler authorizationHandler;
    private final AuthenticateUserResolver authenticateUserResolver;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry
                .addInterceptor(AuthInterceptor.builder(authenticationHandler, authorizationHandler)
                        .anyMatch()
                        .include(GET, "/api/users/authorization").hasRole(ADMIN)
                        .exclude(POST, "/api/users/signup")
                        .exclude(POST, "/api/users/login")
                        .exclude(GET, "/api/users/refresh")
                        .build())
                .order(0);
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(authenticateUserResolver);
    }
}
