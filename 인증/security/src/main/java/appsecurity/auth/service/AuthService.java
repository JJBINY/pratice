package appsecurity.auth.service;

import appsecurity.auth.blacklist.TokenBlackList;
import appsecurity.auth.exception.UnauthenticatedException;
import appsecurity.auth.jwt.JwtType;
import appsecurity.auth.security.EmailPasswordAuthentication;
import appsecurity.auth.security.JwtAuthentication;
import appsecurity.auth.service.dto.AuthTokens;
import appsecurity.auth.service.dto.Login;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class AuthService {
    private final AuthTokensProvider authTokensProvider;
    private final AuthenticationManager authenticationManager;
    private final TokenBlackList tokenBlackList;

    @Transactional
    public AuthTokens login(Login login) {
        log.debug("login process in progress : {}",login);
        var unauthenticated = EmailPasswordAuthentication.unauthenticated(login.email(), login.password());
        var authentication = authenticationManager.authenticate(unauthenticated);
        return authTokensProvider.generate(authentication);
    }

    @Transactional
    public AuthTokens refresh(String refreshToken) {
        log.debug("refresh process in progress : {}",refreshToken);
        var unauthenticated = JwtAuthentication.unauthenticated(refreshToken);
        var authentication = (JwtAuthentication) authenticationManager.authenticate(unauthenticated);
        validateRefresh(authentication);
        return authTokensProvider.generate(authentication);
    }

    private void validateRefresh(JwtAuthentication jwtAuthentication) {
        if(!jwtAuthentication.isAuthenticated()){
            throw new UnauthenticatedException();
        }

        var claims = jwtAuthentication.getDetails();

        if(claims.type() != JwtType.REFRESH){
            throw new UnauthenticatedException("유효하지 않은 타입의 토큰입니다");
        }

        if(tokenBlackList.isBlacked(claims.tokenId())){
            throw new UnauthenticatedException("이미 사용된 토큰입니다");
        }
        tokenBlackList.add(claims.tokenId(), claims.expiresAt());
    }
}
