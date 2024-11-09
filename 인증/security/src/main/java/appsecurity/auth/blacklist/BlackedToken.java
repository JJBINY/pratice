package appsecurity.auth.blacklist;

import appsecurity.common.CreateTimeEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;


@Entity
@Table(name = "blacked_tokens")
@Getter(AccessLevel.PROTECTED)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class BlackedToken extends CreateTimeEntity {
    @Id
    private Long id;
    @Column(nullable = false)
    private Instant expiresAt;

    public BlackedToken(Long id, Instant expiresAt) {
        this.id = id;
        this.expiresAt = expiresAt;
    }
}
