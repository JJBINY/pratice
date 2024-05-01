package app.user.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record Signup(@Email @NotBlank String email,
                     @NotBlank String password,
                     @NotBlank String name) {
}
