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
public class BlackedToken extends CreateTimeEntity { // todo rename, 일단 임시로 blacked token으로 명명
    @Id
    private Long userId;
    private String token;

    @Builder
    public BlackedToken(Long userId, String token) {
        this.userId = userId;
        this.token = token;
    }

    public boolean validate(String token){
        return token.equals(this.token);
    }

    public <X extends Throwable> BlackedToken validate(String token, Supplier<? extends X> exceptionSupplier) throws X {
        if (!validate(token)) {
            throw exceptionSupplier.get();
        }
        return this;
    }
}
