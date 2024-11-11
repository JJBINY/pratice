package appsecurity.auth.security;

import appsecurity.auth.jwt.JwtClaims;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;

public class JwtAuthentication extends AbstractAuthenticationToken implements CustomAuthentication {
    private final UserId principal;
    private final Jwt credentials;
    private final JwtClaims details;

    public static JwtAuthentication unauthenticated(String jwt) {
        return new JwtAuthentication(jwt);
    }

    public static JwtAuthentication authenticated(UserId principal, String jwt, JwtClaims details, Collection<? extends GrantedAuthority> authorities) {
        return new JwtAuthentication(principal, jwt, details, authorities);
    }

    private JwtAuthentication(String jwt) {
        super(null);
        this.principal = null;
        this.credentials = new Jwt(jwt);
        this.details = null;
        setAuthenticated(false);
    }

    private JwtAuthentication(UserId principal, String jwt, JwtClaims details, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = new Jwt(jwt);
        this.details = details;
        super.setAuthenticated(true); // must use super, as we override
    }

    @Override
    public UserId getPrincipal() {
        return this.principal;
    }

    @Override
    public Jwt getCredentials() {
        return this.credentials;
    }

    @Override
    public JwtClaims getDetails() {
        return this.details;
    }

    @Override
    @Deprecated
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated,
                "Cannot set this accessToken to trusted - use constructor which takes a GrantedAuthority list instead");
        super.setAuthenticated(false);
    }

    public record Jwt(String jwt) {
    }
}
