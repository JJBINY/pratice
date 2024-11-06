package appsecurity.auth.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;

public class EmailPasswordAuthentication extends AbstractAuthenticationToken implements CustomAuthentication {
    private final UserId principal;
    private final String email;
    private final Password credentials;

    public static EmailPasswordAuthentication unauthenticated(String email, String password) {
        return new EmailPasswordAuthentication(email, password);
    }

    public static EmailPasswordAuthentication authenticated(UserId principal, Collection<? extends GrantedAuthority> authorities) {
        return new EmailPasswordAuthentication(principal, authorities);
    }

    private EmailPasswordAuthentication(UserId principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.email = null;
        this.credentials = null;
        super.setAuthenticated(true); // must use super, as we override
    }

    private EmailPasswordAuthentication(String email, String password) {
        super(null);
        this.principal = null;
        this.email = email;
        this.credentials = new Password(password);
        setAuthenticated(false);
    }

    @Override
    public UserId getPrincipal() {
        return this.principal;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public Password getCredentials() {
        return this.credentials;
    }

    @Override
    @Deprecated
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated,
                "Cannot set this accessToken to trusted - use constructor which takes a GrantedAuthority list instead");
        super.setAuthenticated(false);
    }

    public record Password(String password){
    }
}
