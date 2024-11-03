package appsecurity.auth.authentication;

import appsecurity.auth.AuthUser;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;

public class EmailPasswordAuthenticationToken extends AbstractAuthenticationToken {
    private AuthUser principal;
    private final String email;
    private String password;

    public EmailPasswordAuthenticationToken(AuthUser principal, String email, String password, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.email = email;
        this.password = password;
        super.setAuthenticated(true); // must use super, as we override
    }

    private EmailPasswordAuthenticationToken(String email, String password) {
        super(null);
        this.email = email;
        this.password = password;
        setAuthenticated(false);
    }

    public static EmailPasswordAuthenticationToken unauthenticated(String email, String password) {
        return new EmailPasswordAuthenticationToken(email, password);
    }

    public static EmailPasswordAuthenticationToken authenticated(AuthUser principal) {
        return new EmailPasswordAuthenticationToken(principal, principal.getUsername(), principal.getPassword(), principal.getAuthorities());
    }

    @Override
    public AuthUser getPrincipal() {
        return this.principal;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public String getCredentials() {
        return this.password;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated,
                "Cannot set this accessToken to trusted - use constructor which takes a GrantedAuthority list instead");
        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.password = null;
    }
}
