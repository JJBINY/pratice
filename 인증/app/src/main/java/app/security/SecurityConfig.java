package app.security;

import app.security.authentication.Jwt;
import app.security.authentication.JwtConfigProps;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtConfigProps jwtConfigProps;

    @Bean
    public Jwt jwt() {
        return new Jwt(jwtConfigProps);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new PasswordEncoder();
    }
}
