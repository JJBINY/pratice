package appsecurity.security;

import appsecurity.security.authorization.Role;
import lombok.Getter;

@Getter
public class UserPrincipal { //todo SpringSecurity가 제공하는 객체로 대체
    private final Long userId;
    private final Role role;

    public UserPrincipal(Long userId, Role role) {
        this.userId = userId;
        this.role = role;
    }
}
