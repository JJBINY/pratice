package appsecurity.auth.service;

import appsecurity.auth.security.AuthUser;
import appsecurity.auth.UserPrincipal;
import appsecurity.auth.security.EmailPasswordAuthentication;
import appsecurity.auth.security.UserId;
import appsecurity.auth.service.dto.AuthResult;
import appsecurity.auth.service.dto.Login;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class AuthService {
    private final AuthUserService authUserService;
    private final AuthTokenGenerator authTokenGenerator;
    private final AuthenticationManager authenticationManager;

    @Transactional
    public AuthResult login(Login login) {
        log.info("login process progress... {}",login);
        var unauthenticated = EmailPasswordAuthentication.unauthenticated(login.email(), login.password());
        log.info("unauthenticated");
        var authenticated = authenticationManager.authenticate(unauthenticated);
        log.info("authenticated");
        return getAuthResult(authenticated);
    }

    @Transactional
    public AuthResult refresh(UserPrincipal userPrincipal) {
        AuthUser authUser = authUserService.loadUserById(userPrincipal.getUserId());
        var authenticated = EmailPasswordAuthentication.authenticated(new UserId(authUser.getUserId()), authUser.getAuthorities());
        log.info("[REFRESH] userId = {}", authUser.getUserId());
        return getAuthResult(authenticated);
    }

    private AuthResult getAuthResult(Authentication authentication) {
        var authToken = authTokenGenerator.generateToken(authentication);
        return new AuthResult(authToken.forAccess(), authToken.forRefresh());
    }
    // todo logout
}
