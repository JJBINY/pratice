package appsecurity.auth.service;

import appsecurity.auth.*;
import appsecurity.auth.jwt.JwtType;
import appsecurity.auth.security.AuthUser;
import appsecurity.auth.security.EmailPasswordAuthenticationToken;
import appsecurity.auth.jwt.JwtProvider;
import appsecurity.auth.repository.AuthTokenRepository;
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
        if(!authentication.isAuthenticated()){ // precondition
            throw new IllegalArgumentException("인증되지 않은 인증정보로는 토큰을 생성할 수 없습니다");
        }

        Long userId; // todo UserId record 생성; 보편 언어
        List<String> roles;

        if (authentication instanceof EmailPasswordAuthenticationToken) {
            AuthUser authUser = ((EmailPasswordAuthenticationToken) authentication).getPrincipal();
            userId = authUser.getUserId();
            roles = authUser.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
        }else{
            throw new IllegalArgumentException("지원하지 않은 형태의 인증 정보입니다");
        }

        return AuthToken.builder()
                .forAccess(generateToken(userId, roles))
                .forRefresh(generateRefresh(userId, roles))
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
    public record AuthToken(String forAccess, String forRefresh){}
}
