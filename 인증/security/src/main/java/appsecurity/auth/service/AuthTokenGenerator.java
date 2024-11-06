package appsecurity.auth.service;

import appsecurity.auth.*;
import appsecurity.auth.jwt.JwtType;
import appsecurity.auth.security.CustomAuthentication;
import appsecurity.auth.security.EmailPasswordAuthentication;
import appsecurity.auth.jwt.JwtProvider;
import appsecurity.auth.repository.AuthTokenRepository;
import appsecurity.auth.security.UserId;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class AuthTokenGenerator {
    private final JwtProvider jwtProvider;
    private final AuthTokenRepository authTokenRepository; // todo refactor blacklist repo

    public AuthToken generateToken(Authentication authentication) {
        if (!authentication.isAuthenticated()) { // precondition
            throw new IllegalArgumentException("인증되지 않은 인증정보로는 토큰을 생성할 수 없습니다");
        }

        if (!(authentication instanceof CustomAuthentication)) { // precondition
            throw new IllegalArgumentException("지원하지 않는 형태의 인증 정보입니다");
        }

        UserId userId = ((EmailPasswordAuthentication) authentication).getPrincipal();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return AuthToken.builder()
                .forAccess(generateToken(userId.userId(), roles))
                .forRefresh(generateRefresh(userId.userId(), roles))
                .build();
    }

    private String generateToken(Long userId, List<String> roles) {

        return jwtProvider.createToken(userId, roles, JwtType.ACCESS);
    }

    private String generateRefresh(Long userId, List<String> roles) {
        String token = jwtProvider.createToken(userId, roles, JwtType.REFRESH);
        BlackedToken refresh = BlackedToken.builder()
                .userId(userId)
                .token(token)
                .build();
        authTokenRepository.save(refresh); //todo 이름 변경
        return token;
    }

    @Builder
    public record AuthToken(String forAccess, String forRefresh) {
    }
}
