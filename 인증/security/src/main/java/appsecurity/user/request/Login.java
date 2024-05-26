package appsecurity.user.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record Login(@Email @NotBlank String email, @NotBlank String password) {
}
