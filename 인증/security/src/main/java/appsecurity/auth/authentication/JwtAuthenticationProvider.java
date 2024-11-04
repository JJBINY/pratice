package appsecurity.auth.authentication;

import appsecurity.auth.jwt.JwtProvider;
import appsecurity.auth.jwt.JwtValidationException;
import appsecurity.auth.service.AuthUserService;
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
    private final AuthUserService authUserService;
    private final JwtProvider jwtProvider;
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var authenticationToken = (JwtAuthenticationToken) authentication;
        var jwt = authenticationToken.getCredentials();

        try {
            var claims = jwtProvider.validate(jwt);
            var authorities = claims.roles().stream().map(SimpleGrantedAuthority::new).toList();
            log.warn("토큰 검증 성공: 권한 = {}", authorities);
            var authUser = authUserService.loadUserById(claims.userId()); // todo DB 조회 안하도록 로직 수정; 현재는 토큰을 쓰는 의미가 퇴색됨
            System.out.println("authUser.getAuthorities() = " + authUser.getAuthorities());
            return JwtAuthenticationToken.authenticated(authUser);
        } catch (JwtValidationException e) {
            log.warn("토큰 검증 실패 = {}", e.getMessage());
            return JwtAuthenticationToken.unauthenticated(jwt);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(JwtAuthenticationToken.class);
    }
}
