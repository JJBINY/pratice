package appsecurity.auth.authentication;

import appsecurity.auth.AuthUser;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private final AuthUser principal;
    private final String jwt; // jwt; string보다는 JWT타입(record) 생성해서 할당

    public static JwtAuthenticationToken unauthenticated(String jwt) {
        return new JwtAuthenticationToken(jwt);
    }

    public static JwtAuthenticationToken authenticated(AuthUser principal) {
        return new JwtAuthenticationToken(principal, principal.getAuthorities());
    }

    private JwtAuthenticationToken(String jwt) {
        super(null);
        this.principal = null;
        this.jwt = jwt;
        setAuthenticated(false);
    }

    private JwtAuthenticationToken(AuthUser principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.jwt = null;
        super.setAuthenticated(true); // must use super, as we override
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public String getCredentials() {
        return this.jwt;
    }

    @Override
    @Deprecated
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated,
                "Cannot set this accessToken to trusted - use constructor which takes a GrantedAuthority list instead");
        super.setAuthenticated(false);
    }
}
