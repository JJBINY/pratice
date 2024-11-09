package appsecurity.auth.controller;

import appsecurity.auth.jwt.Jwt;
import appsecurity.auth.service.AuthService;
import appsecurity.auth.controller.dto.LoginRequest;
import appsecurity.auth.controller.dto.AuthResponse;
import appsecurity.auth.service.dto.Login;
import appsecurity.auth.service.dto.AuthTokens;
import com.google.common.net.HttpHeaders;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import static java.util.Objects.isNull;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid LoginRequest request) {
        log.debug("login request = {}", request);
        AuthTokens authTokens = authService.login(Login.builder()
                .email(request.email())
                .password(request.password())
                .build());
        log.debug("login success for = {}", request);
        return generateAuthResponse(authTokens);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@CookieValue(value = "refreshToken") String refreshToken) {
        log.debug("refresh request = {}", refreshToken);
        AuthTokens authTokens = authService.refresh(refreshToken);
        return generateAuthResponse(authTokens);
    }

    @GetMapping("/authentication")
    public ResponseEntity<String> authentication() {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body("인증 테스트 성공");
    }

    @GetMapping("/authorization")
    public ResponseEntity<String> authorization() {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body("인가 테스트 성공");
    }

    private static ResponseEntity<AuthResponse> generateAuthResponse(AuthTokens authTokens) {
        String refreshCookie = generateRefreshCookie(authTokens.forRefresh());
        return ResponseEntity
                .status(HttpStatus.OK)
                .contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.SET_COOKIE, refreshCookie)
                .body(AuthResponse.builder()
                        .accessToken(authTokens.forAccess().value())
                        .build());
    }

    private static String generateRefreshCookie(Jwt refreshToken) {
        return ResponseCookie
                .from("refreshToken", refreshToken.value())
                .domain("jjbiny.practice")
                .path("/api/auth/refresh")
                .httpOnly(true)
                .secure(true)
                .maxAge(refreshToken.expirySeconds())
                .sameSite("Strict")
                .build().toString();
    }
}
