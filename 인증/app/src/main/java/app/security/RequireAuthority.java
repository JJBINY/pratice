package app.security;

import app.user.Role;

import java.lang.annotation.*;

@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequireAuthority {
    Role[] authorities();
}
