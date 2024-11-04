package appsecurity.auth.authentication;

import appsecurity.auth.AuthUser;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;

public class EmailPasswordAuthenticationToken extends AbstractAuthenticationToken {
    private final AuthUser principal;
    private final String email;
    private final String password;

    public static EmailPasswordAuthenticationToken unauthenticated(String email, String password) {
        return new EmailPasswordAuthenticationToken(email, password);
    }

    public static EmailPasswordAuthenticationToken authenticated(AuthUser principal) {
        return new EmailPasswordAuthenticationToken(principal, principal.getAuthorities());
    }

    private EmailPasswordAuthenticationToken(AuthUser principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.email = null;
        this.password = null;
        super.setAuthenticated(true); // must use super, as we override
    }

    private EmailPasswordAuthenticationToken(String email, String password) {
        super(null);
        this.principal = null;
        this.email = email;
        this.password = password;
        setAuthenticated(false);
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
    @Deprecated
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated,
                "Cannot set this accessToken to trusted - use constructor which takes a GrantedAuthority list instead");
        super.setAuthenticated(false);
    }
}
