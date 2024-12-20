package appsecurity.user.controller.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record SignupRequest(@Email @NotBlank String email,
                            @NotBlank String password,
                            @NotBlank String name) {
}
