package appsecurity.security.authentication;

import appsecurity.security.UserPrincipal;
import appsecurity.security.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthenticationProvider {
    private final JwtProvider jwtProvider;
    private final RefreshRepository refreshRepository;

    public String createToken(UserPrincipal userPrincipal) {
        return jwtProvider.generateToken(userPrincipal, TokenType.ACCESS);
    }

    public String createRefresh(UserPrincipal userPrincipal) {
        Refresh refresh = Refresh.builder()
                .userId(userPrincipal.getUserId())
                .token(jwtProvider.generateToken(userPrincipal, TokenType.REFRESH))
                .build();
        refreshRepository.save(refresh);
        return refresh.getToken();
    }

}
