package appsecurity.user.service.dto;

import lombok.Builder;

@Builder
public record Signup(String email, String password, String name) {
}
