package appsecurity.security.controller;

import appsecurity.security.service.AuthService;
import appsecurity.security.UserPrincipal;
import appsecurity.security.authentication.AuthenticateUser;
import appsecurity.security.controller.dto.LoginRequest;
import appsecurity.security.controller.dto.AuthResponse;
import appsecurity.security.service.dto.Login;
import appsecurity.security.service.dto.LoginResult;
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
        LoginResult result = authService.login(Login.builder()
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
        LoginResult result = authService.refresh(userPrincipal);

        return ResponseEntity
                .status(HttpStatus.OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body(AuthResponse.builder()
                        .accessToken(result.token())
                        .refreshToken(result.refresh())
                        .build());
    }
}
