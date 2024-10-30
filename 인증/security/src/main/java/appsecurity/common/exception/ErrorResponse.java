package appsecurity.common.exception;

import lombok.Builder;

@Builder
public record ErrorResponse(String message) {
}
