package appsecurity.security.authentication;

import appsecurity.security.UserPrincipal;
import appsecurity.security.jwt.Jwt;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthenticationProvider {
    private final Jwt jwt;
    private final RefreshRepository refreshRepository;

    public String createToken(UserPrincipal userPrincipal) {
        return jwt.create(userPrincipal, TokenType.ACCESS);
    }

    public String createRefresh(UserPrincipal userPrincipal) {
        Refresh refresh = Refresh.builder()
                .userId(userPrincipal.getUserId())
                .token(jwt.create(userPrincipal, TokenType.REFRESH))
                .build();
        refreshRepository.save(refresh);
        return refresh.getToken();
    }

}
