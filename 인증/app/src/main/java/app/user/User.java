package app.user;

import app.common.BaseTimeEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.util.Objects;


@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "users")
@Getter
public class User extends BaseTimeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Email
    @Column(unique = true, nullable = false)
    private String email;
    @Column(nullable = false)
    private String password;
    @Column(nullable = false)
    private String name;

    @Builder
    private User(String email, String password, String name) {
        this.email = email;
        this.password = password;
        this.name = name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User user)) return false;

        if (!Objects.equals(id, user.id)) return false;
        if (!Objects.equals(email, user.email)) return false;
        if (!Objects.equals(password, user.password)) return false;
        return Objects.equals(name, user.name);
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (email != null ? email.hashCode() : 0);
        result = 31 * result + (password != null ? password.hashCode() : 0);
        result = 31 * result + (name != null ? name.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this,ToStringStyle.MULTI_LINE_STYLE)
                .append("id", id)
                .append("email",email)
                .append("password","[PROTECTED]")
                .append("name",name)
                .append("createAt", getCreatedAt())
                .append("lastModifiedAt",getLastModifiedAt())
                .build();
    }
}
