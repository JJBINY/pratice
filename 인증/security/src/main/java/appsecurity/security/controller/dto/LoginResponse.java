package appsecurity.security.controller.dto;

import lombok.Builder;

@Builder
public record LoginResponse(String token, String refresh) {
}
