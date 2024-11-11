package appsecurity.auth.service;

import appsecurity.auth.blacklist.TokenBlackList;
import appsecurity.auth.exception.UnauthenticatedException;
import appsecurity.auth.jwt.JwtClaims;
import appsecurity.auth.jwt.JwtType;
import appsecurity.auth.security.EmailPasswordAuthentication;
import appsecurity.auth.security.JwtAuthentication;
import appsecurity.auth.service.dto.AuthTokens;
import appsecurity.auth.service.dto.Login;
import appsecurity.auth.service.dto.Logout;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
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
        return authTokensProvider.generate(validate(refreshToken, JwtType.REFRESH));
    }

    @Transactional
    public void logout(Logout logout) {
        log.debug("logout process in progress : {}",logout);
        validate(logout.accessToken(), JwtType.ACCESS);
        validate(logout.refreshToken(), JwtType.REFRESH);
    }

    private Authentication validate(String token, JwtType type) {
        var unauthenticated = JwtAuthentication.unauthenticated(token);
        var jwtAuthentication = (JwtAuthentication) authenticationManager.authenticate(unauthenticated);

        if(!jwtAuthentication.isAuthenticated()){
            throw new UnauthenticatedException();
        }

        validate(jwtAuthentication.getDetails(), type);
        return jwtAuthentication;
    }

    private void validate(JwtClaims claims, JwtType type) {
        if(claims.type() != type){
            throw new UnauthenticatedException("유효하지 않은 타입의 토큰입니다");
        }

        if(tokenBlackList.isBlacked(claims.tokenId())){
            throw new UnauthenticatedException("이미 사용된 토큰입니다");
        }
        tokenBlackList.add(claims.tokenId(), claims.expiresAt());
    }
}
