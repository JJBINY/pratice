package app.security.authentication;

import app.common.CreateTimeEntity;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;


@Entity
@Table(name = "refreshes")
@Getter(AccessLevel.PROTECTED)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Refresh extends CreateTimeEntity {
    @Id
    private Long userId;
    private String token;

    @Builder
    public Refresh(Long userId, String token) {
        this.userId = userId;
        this.token = token;
    }
}
