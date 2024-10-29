package appsecurity.security.controller.dto;

import lombok.Builder;

@Builder
public record AuthResponse(String accessToken, String refreshToken) {
}
