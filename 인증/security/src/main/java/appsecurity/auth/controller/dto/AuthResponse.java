package appsecurity.auth.controller.dto;

import lombok.Builder;

@Builder
public record AuthResponse(String accessToken) {
}
