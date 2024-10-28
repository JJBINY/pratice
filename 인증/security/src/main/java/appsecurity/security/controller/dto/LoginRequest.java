package appsecurity.security.controller.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record LoginRequest(@Email @NotBlank String email, @NotBlank String password) {
}
