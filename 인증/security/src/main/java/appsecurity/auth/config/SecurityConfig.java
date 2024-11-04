package appsecurity.auth.config;

import appsecurity.auth.Role;
import appsecurity.auth.authentication.EmailPasswordAuthenticationProvider;
import appsecurity.auth.authentication.JwtAuthenticationFilter;
import appsecurity.auth.authentication.JwtAuthenticationProvider;
import appsecurity.auth.handler.CustomAuthenticationEntryPoint;
import appsecurity.auth.handler.CustomAccessDeniedHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final AuthProps authProps;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;
    private final EmailPasswordAuthenticationProvider emailPasswordAuthenticationProvider;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/resources/**").denyAll()
                        .requestMatchers(POST, "/api/users/signup").permitAll()
                        .requestMatchers(GET, "/api/users/authorization").hasRole(Role.ADMIN.name())
                        .anyRequest().authenticated())
                .exceptionHandling(eh -> eh
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler))
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(emailPasswordAuthenticationProvider, jwtAuthenticationProvider);
    }

    private JwtAuthenticationFilter jwtAuthenticationFilter(){
        return new JwtAuthenticationFilter(authProps, authenticationManager());
    }
}
