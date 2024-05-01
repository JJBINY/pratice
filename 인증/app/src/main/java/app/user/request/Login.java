package app.user.request;

import lombok.Builder;

@Builder
public record Login(String email, String password) {
}
