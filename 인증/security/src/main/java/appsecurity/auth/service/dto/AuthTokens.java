package appsecurity.auth.service.dto;

import appsecurity.auth.jwt.Jwt;
import lombok.Builder;

@Builder
public record AuthTokens(Jwt forAccess, Jwt forRefresh) {
}
