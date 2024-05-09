package app.common;

import app.security.authentication.AuthenticateUserResolver;
import app.security.authentication.JwtAuthenticationInterceptor;
import app.security.authorization.AuthorizationInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class WebMvcConfig implements WebMvcConfigurer {

    private final JwtAuthenticationInterceptor jwtAuthenticationInterceptor;
    private final AuthorizationInterceptor authorizationInterceptor;
    private final AuthenticateUserResolver authenticateUserResolver;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry
                .addInterceptor(jwtAuthenticationInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/users/signup")
                .excludePathPatterns("/api/users/login")
                .excludePathPatterns("/api/users/refresh")
                .order(0);
        registry
                .addInterceptor(authorizationInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/users/signup")
                .excludePathPatterns("/api/users/login")
                .excludePathPatterns("/api/users/refresh")
                .order(1);
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(authenticateUserResolver);
    }
}
