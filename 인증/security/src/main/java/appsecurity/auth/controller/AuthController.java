package appsecurity.auth.controller;

import appsecurity.auth.service.AuthService;
import appsecurity.auth.UserPrincipal;
import appsecurity.auth.AuthenticateUser;
import appsecurity.auth.controller.dto.LoginRequest;
import appsecurity.auth.controller.dto.AuthResponse;
import appsecurity.auth.service.dto.Login;
import appsecurity.auth.service.dto.AuthResult;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid LoginRequest request) {
        log.info("login request = {}",request);
        AuthResult result = authService.login(Login.builder()
                .email(request.email())
                .password(request.password())
                .build());
        log.info("login success for = {}",request);
        return ResponseEntity
                .status(HttpStatus.OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body(AuthResponse.builder()
                        .accessToken(result.token())
                        .refreshToken(result.refresh()) // todo refresh token은 http-only, samesite=strict 등이 적용된 쿠키로 전달
                        .build());
    }

    @GetMapping("/refresh") // todo 전체적인 리프래시 과정 리팩토링
    public ResponseEntity<AuthResponse> refresh(@AuthenticateUser UserPrincipal userPrincipal) {
        AuthResult result = authService.refresh(userPrincipal);

        return ResponseEntity
                .status(HttpStatus.OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body(AuthResponse.builder()
                        .accessToken(result.token())
                        .refreshToken(result.refresh())
                        .build());
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
}
