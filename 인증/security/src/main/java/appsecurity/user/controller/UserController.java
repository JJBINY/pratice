package appsecurity.user.controller;

import appsecurity.security.UserPrincipal;
import appsecurity.security.authentication.AuthenticateUser;
import appsecurity.user.controller.dto.LoginResponse;
import appsecurity.user.service.UserService;
import appsecurity.user.controller.dto.LoginRequest;
import appsecurity.user.controller.dto.SignupRequest;
import appsecurity.user.service.dto.LoginResult;
import appsecurity.user.service.dto.Login;
import appsecurity.user.service.dto.Signup;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<Object> signup(@RequestBody @Valid SignupRequest request) {
        userService.signup(Signup.builder()
                .email(request.email())
                .password(request.password())
                .name(request.name())
                .build());

        return ResponseEntity
                .status(HttpStatus.NO_CONTENT)
                .build();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest request) {
        log.info("login api request = {}", request);
        LoginResult result = userService.login(Login.builder()
                .email(request.email())
                .password(request.password())
                .build());

        log.info("login api success");
        return ResponseEntity
                .status(HttpStatus.OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body(LoginResponse.builder()
                        .token(result.token())
                        .refresh(result.refresh())
                        .build());
    }

    @GetMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@AuthenticateUser UserPrincipal userPrincipal) {
        LoginResult result = userService.refresh(userPrincipal);

        return ResponseEntity
                .status(HttpStatus.OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body(LoginResponse.builder()
                        .token(result.token())
                        .refresh(result.refresh())
                        .build());
    }

    @GetMapping("/authentication")
    public ResponseEntity<String> authentication() {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body("인증성공");
    }

    @GetMapping("/authorization")
    public ResponseEntity<String> authorization() {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body("인가성공");
    }
}
