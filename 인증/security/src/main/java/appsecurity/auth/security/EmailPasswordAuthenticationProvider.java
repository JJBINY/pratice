package appsecurity.auth.security;

import appsecurity.auth.AuthUser;
import appsecurity.auth.exception.UnauthenticatedException;
import appsecurity.auth.service.AuthUserService;
import appsecurity.common.PasswordEncoder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class EmailPasswordAuthenticationProvider implements AuthenticationProvider{
    private final AuthUserService authUserService;
    private final PasswordEncoder passwordEncoder;
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("EmailPasswordAuthenticationProvider.authenticate for = {}",authentication);
        var authenticationToken = (EmailPasswordAuthenticationToken) authentication; // todo 가독성 리팩토링 var 키워드 사용
        var email = authenticationToken.getEmail();
        var password = authenticationToken.getCredentials();
        AuthUser authUser = authUserService.loadUserByEmail(email);

        if (!passwordEncoder.matches(password, authUser.getPassword())) {
            throw new UnauthenticatedException("Invalid password");
        }

        return EmailPasswordAuthenticationToken.authenticated(authUser);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(EmailPasswordAuthenticationToken.class);
    }
}
