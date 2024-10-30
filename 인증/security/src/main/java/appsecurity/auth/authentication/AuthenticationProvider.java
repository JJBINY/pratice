package appsecurity.auth.authentication;

import appsecurity.auth.AuthToken;
import appsecurity.auth.repository.AuthTokenRepository;
import appsecurity.auth.TokenType;
import appsecurity.auth.UserPrincipal;
import appsecurity.auth.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthenticationProvider {
    private final JwtProvider jwtProvider;
    private final AuthTokenRepository authTokenRepository;

    public String generateToken(UserPrincipal userPrincipal) {
        return jwtProvider.createToken(userPrincipal, TokenType.ACCESS);
    }

    public String generateRefresh(UserPrincipal userPrincipal) {
        String token = jwtProvider.createToken(userPrincipal, TokenType.REFRESH);
        AuthToken refresh = AuthToken.builder()
                .userId(userPrincipal.getUserId())
                .token(token)
                .build();
        authTokenRepository.save(refresh);
        return token;
    }

//    public record AuthHolder(String accessToken, String refreshToken){ }
}
