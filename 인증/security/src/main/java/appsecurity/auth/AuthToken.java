package appsecurity.auth;

import appsecurity.common.CreateTimeEntity;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.function.Supplier;


@Entity
@Table(name = "auth_tokens")
@Getter(AccessLevel.PROTECTED)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuthToken extends CreateTimeEntity {
    @Id
    private Long userId;
    private String token;

    @Builder
    public AuthToken(Long userId, String token) {
        this.userId = userId;
        this.token = token;
    }

    public boolean validate(String token){
        return token.equals(this.token);
    }

    public <X extends Throwable> AuthToken validate(String token, Supplier<? extends X> exceptionSupplier) throws X {
        if (!validate(token)) {
            throw exceptionSupplier.get();
        }
        return this;
    }
}
