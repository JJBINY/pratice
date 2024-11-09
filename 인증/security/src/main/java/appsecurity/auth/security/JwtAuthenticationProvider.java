package appsecurity.auth.security;

import appsecurity.auth.jwt.JwtProvider;
import appsecurity.auth.jwt.JwtValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider{
    private final JwtProvider jwtProvider;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var jwtAuthenticationToken = (JwtAuthentication) authentication;
        var credentials = jwtAuthenticationToken.getCredentials();

        try {
            var claims = jwtProvider.validate(credentials.jwt());
            var authorities = claims.roles().stream().map(SimpleGrantedAuthority::new).toList();
            log.debug("토큰 검증 성공: 권한 = {}", authorities);
            return JwtAuthentication.authenticated(new UserId(claims.userId()), claims, authorities);
        } catch (JwtValidationException e) {
            log.warn("토큰 검증 실패 = {}", e.getMessage());
            return JwtAuthentication.unauthenticated(credentials.jwt());
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(JwtAuthentication.class);
    }
}
