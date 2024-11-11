package appsecurity.auth.security;

import appsecurity.auth.blacklist.TokenBlackList;
import appsecurity.auth.jwt.JwtValidationException;
import appsecurity.auth.jwt.JwtValidator;
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
    private final JwtValidator jwtValidator;
    private final TokenBlackList tokenBlackList;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var jwtAuthentication = (JwtAuthentication) authentication;
        var credentials = jwtAuthentication.getCredentials();
        try {
            return authenticate(credentials.jwt());
        } catch (JwtValidationException e) {
            log.warn("토큰 검증 실패 = {}", e.getMessage());
            return JwtAuthentication.unauthenticated(credentials.jwt());
        }
    }

    private JwtAuthentication authenticate(String jwt) throws JwtValidationException {
        var claims = jwtValidator.validate(jwt);

        if (tokenBlackList.isBlacked(claims.tokenId())) {
            throw new JwtValidationException("블랙리스트에 등록된 토큰");
        }

        var authorities = claims.roles().stream().map(SimpleGrantedAuthority::new).toList();
        log.debug("토큰 검증 성공: 권한 = {}", authorities);
        return JwtAuthentication.authenticated(new UserId(claims.userId()), jwt, claims, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(JwtAuthentication.class);
    }
}
