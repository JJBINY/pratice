package appsecurity.user;

import appsecurity.security.UserPrincipal;
import appsecurity.security.authentication.AuthenticateUser;
import appsecurity.user.request.LoginRequest;
import appsecurity.user.request.SignupRequest;
import appsecurity.user.response.LoginResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<Object> signup(@RequestBody @Valid SignupRequest request) {
        userService.signup(request);
        return ResponseEntity
                .status(HttpStatus.NO_CONTENT)
                .build();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest request) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body(userService.login(request));
    }

    @GetMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@AuthenticateUser UserPrincipal userPrincipal) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body(userService.refresh(userPrincipal));
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
