package appsecurity.auth.controller;

import appsecurity.auth.service.AuthService;
import appsecurity.auth.UserPrincipal;
import appsecurity.auth.authentication.AuthenticateUser;
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
        AuthResult result = authService.login(Login.builder()
                .email(request.email())
                .password(request.password())
                .build());

        return ResponseEntity
                .status(HttpStatus.OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body(AuthResponse.builder()
                        .accessToken(result.token())
                        .refreshToken(result.refresh())
                        .build());
    }

    @GetMapping("/refresh")
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
}
