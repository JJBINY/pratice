package appsecurity.user;

import appsecurity.common.AssertionMessage;
import appsecurity.common.BaseTimeEntity;
import appsecurity.security.authorization.Role;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.springframework.util.Assert;

import java.util.Objects;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static org.apache.commons.lang3.EnumUtils.isValidEnum;
import static org.apache.commons.lang3.ObjectUtils.isEmpty;
import static org.apache.commons.lang3.ObjectUtils.isNotEmpty;


@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
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

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Role role;

    @Builder
    private User(String email, String password, String name, Role role) {
        checkArgument(isNotEmpty(email));
        checkArgument(isNotEmpty(password));
        checkArgument(isNotEmpty(name));
        checkArgument(isEmpty(role) || isValidEnum(Role.class, role.name()));

        this.email = email;
        this.password = password;
        this.name = name;
        this.role = (role == null ? Role.USER : role);

        Assert.isTrue(isNotEmpty(this.email), AssertionMessage.NOT_EMPTY);
        Assert.isTrue(isNotEmpty(this.password), AssertionMessage.NOT_EMPTY);
        Assert.isTrue(isNotEmpty(this.name), AssertionMessage.NOT_EMPTY);
        Assert.isTrue(isValidEnum(Role.class, this.role.name()), AssertionMessage.VALID);
    }

    public void changeRole(Role role) {
        checkNotNull(role);
        this.role = role;
        assert (isValidEnum(Role.class, role.name()));
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
        return new ToStringBuilder(this, ToStringStyle.MULTI_LINE_STYLE)
                .append("id", id)
                .append("email", email)
                .append("password", "[PROTECTED]")
                .append("name", name)
                .append("createAt", getCreatedAt())
                .append("lastModifiedAt", getLastModifiedAt())
                .build();
    }
}
