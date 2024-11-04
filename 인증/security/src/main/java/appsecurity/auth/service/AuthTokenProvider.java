package appsecurity.auth.service;

import appsecurity.auth.*;
import appsecurity.auth.security.EmailPasswordAuthenticationToken;
import appsecurity.auth.jwt.JwtProvider;
import appsecurity.auth.repository.AuthTokenRepository;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthTokenProvider {
    private final JwtProvider jwtProvider;
    private final AuthTokenRepository authTokenRepository;

    public AuthToken generateToken(Authentication authentication){
        if(authentication instanceof EmailPasswordAuthenticationToken) {
            AuthUser authUser = ((EmailPasswordAuthenticationToken) authentication).getPrincipal();
            return AuthToken.builder()
                    .forAccess(generateToken(authUser))
                    .forRefresh(generateRefresh(authUser))
                    .build();
        }
        throw new IllegalArgumentException("지원하지 않은 형태의 인증 정보입니다.");
    }
    private String generateToken(AuthUser authUser) {
        return jwtProvider.createToken(authUser, TokenType.ACCESS);
    }

    private String generateRefresh(AuthUser authUser) {
        String token = jwtProvider.createToken(authUser, TokenType.REFRESH);
        BlackedToken refresh = BlackedToken.builder()
                .userId(authUser.getUserId())
                .token(token)
                .build();
        authTokenRepository.save(refresh); //todo 이름 변경
        return token;
    }

    @Builder
    public record AuthToken(String forAccess, String forRefresh){}
}
