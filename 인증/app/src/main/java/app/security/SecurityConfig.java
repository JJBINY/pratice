package app.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtConfigProps jwtConfigProps;

    @Bean
    public Jwt jwt(){
        return Jwt.builder()
                .issuer(jwtConfigProps.issuer)
                .secret(jwtConfigProps.secret)
                .expirySeconds(jwtConfigProps.expirySeconds)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new PasswordEncoder();
    }
}
