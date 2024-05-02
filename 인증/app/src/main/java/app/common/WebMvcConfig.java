package app.common;

import app.security.AuthorizationInterceptor;
import app.security.JwtAuthenticationInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@RequiredArgsConstructor
public class WebMvcConfig implements WebMvcConfigurer {

    private final JwtAuthenticationInterceptor jwtAuthenticationInterceptor;
    private final AuthorizationInterceptor authorizationInterceptor;
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry
                .addInterceptor(jwtAuthenticationInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/users/signup")
                .excludePathPatterns("/api/users/login")
                .order(0);
        registry
                .addInterceptor(authorizationInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/users/signup")
                .excludePathPatterns("/api/users/login")
                .order(1);

    }
}
