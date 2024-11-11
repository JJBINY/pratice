package appsecurity.auth.service.dto;

import lombok.Builder;

@Builder
public record Logout(String accessToken, String refreshToken) {
}
