package appsecurity.auth.service;

import appsecurity.auth.AuthUser;
import appsecurity.auth.UserPrincipal;
import appsecurity.auth.authentication.EmailPasswordAuthenticationToken;
import appsecurity.auth.service.dto.AuthResult;
import appsecurity.auth.service.dto.Login;
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
    private final AuthUserService authUserService;
    private final AuthTokenProvider authTokenProvider;
    private final AuthenticationManager authenticationManager;

    @Transactional
    public AuthResult login(Login login) {
        log.info("login process progress... {}",login);
        var unauthenticated = EmailPasswordAuthenticationToken.unauthenticated(login.email(), login.password());
        log.info("unauthenticated");
        var authenticated = authenticationManager.authenticate(unauthenticated);
        log.info("authenticated");
        return getAuthResult(authenticated);
    }

    @Transactional
    public AuthResult refresh(UserPrincipal userPrincipal) {
        AuthUser authUser = authUserService.loadUserById(userPrincipal.getUserId());
        EmailPasswordAuthenticationToken authenticated = EmailPasswordAuthenticationToken.authenticated(authUser);
        log.info("[REFRESH] userId = {}", authUser.getUserId());
        return getAuthResult(authenticated);
    }

    private AuthResult getAuthResult(Authentication authentication) {
        var authToken = authTokenProvider.generateToken(authentication);
        return new AuthResult(authToken.forAccess(), authToken.forRefresh());
    }

    // todo logout
}
