package app.security;

import app.security.authorization.Role;
import lombok.Getter;

@Getter
public class UserPrincipal {
    private final Long userId;
    private final Role role;

    public UserPrincipal(Long userId, Role role) {
        this.userId = userId;
        this.role = role;
    }
}
