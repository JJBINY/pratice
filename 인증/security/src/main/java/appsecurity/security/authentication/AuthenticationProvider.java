package appsecurity.security.authentication;

import appsecurity.security.AuthToken;
import appsecurity.security.AuthTokenRepository;
import appsecurity.security.UserPrincipal;
import appsecurity.security.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthenticationProvider {
    private final JwtProvider jwtProvider;
    private final AuthTokenRepository authTokenRepository;

    public String generateToken(UserPrincipal userPrincipal) {
        return jwtProvider.generateToken(userPrincipal, TokenType.ACCESS);
    }

    public String generateRefresh(UserPrincipal userPrincipal) {
        String token = jwtProvider.generateToken(userPrincipal, TokenType.REFRESH);
        AuthToken refresh = AuthToken.builder()
                .userId(userPrincipal.getUserId())
                .token(token)
                .build();
        authTokenRepository.save(refresh);
        return token;
    }

}
