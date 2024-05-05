package app.security;

import app.security.authorization.RequireAuthority;
import app.user.Role;
import app.user.User;
import app.user.UserService;
import app.user.request.Login;
import app.user.request.Signup;
import app.user.response.LoginResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final UserService userService;
    private final Jwt jwt;

    @PostMapping("/signup")
    public ResponseEntity<Object> signup(@RequestBody @Valid Signup request) {
        userService.signup(request);
        return ResponseEntity
                .status(HttpStatus.NO_CONTENT)
                .build();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody @Valid Login request) {
        User user = userService.login(request);
        log.info("[로그인] userId = {} ", user.getId());
        return ResponseEntity
                .status(HttpStatus.OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body(new LoginResponse(jwt.create(user), jwt.createRefresh(user)));
    }

    @GetMapping("/authentication")
    public ResponseEntity<String> authentication() {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body("인증성공");
    }

    @GetMapping("/authorization")
    @RequireAuthority(authorities = {Role.ADMIN})
    public ResponseEntity<String> authorization() {
        return ResponseEntity
                .status(HttpStatus.OK)
                .body("인가성공");
    }
}
