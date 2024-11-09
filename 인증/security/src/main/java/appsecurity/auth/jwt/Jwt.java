package appsecurity.auth.jwt;

import lombok.Builder;

@Builder
public record Jwt(String value, Long expirySeconds) {
}
