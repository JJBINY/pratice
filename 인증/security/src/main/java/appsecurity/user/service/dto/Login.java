package appsecurity.user.service.dto;

import lombok.Builder;

@Builder
public record Login(String email, String password) {
}
