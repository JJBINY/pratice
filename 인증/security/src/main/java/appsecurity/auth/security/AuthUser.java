package appsecurity.auth.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class AuthUser extends User {
    private final Long id;

    public AuthUser(Long id, String email, String password, Collection<? extends GrantedAuthority> authorities) {
        super(email, password, authorities);
        this.id = id;
    }

    public Long getId() {
        return id;
    }
}
