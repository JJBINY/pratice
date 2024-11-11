package appsecurity.auth.service.dto;

import appsecurity.auth.jwt.SignedJwt;
import lombok.Builder;

@Builder
public record AuthTokens(SignedJwt forAccess, SignedJwt forRefresh) {
}
