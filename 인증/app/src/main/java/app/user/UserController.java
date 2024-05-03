package app.user;

import app.security.Jwt;
import app.security.RequireAuthority;
import app.user.request.Login;
import app.user.request.Signup;
import app.user.response.LoginResponse;
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
    private final Jwt jwt;

    @PostMapping("/signup")
    public ResponseEntity<Object> signup(@RequestBody @Valid Signup request){
        userService.signup(request);
        return ResponseEntity
                .status(HttpStatus.NO_CONTENT)
                .build();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody Login request){
        User user = userService.login(request);
        return ResponseEntity
                .status(HttpStatus.OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body(new LoginResponse(user.getId(), jwt.create(user)));
    }

    @GetMapping("/authentication")
    public ResponseEntity<String> authentication(){
        return ResponseEntity
                .status(HttpStatus.OK)
                .body("인증성공");
    }

    @GetMapping("/authorization")
    @RequireAuthority(authorities = {Role.ADMIN})
    public ResponseEntity<String> authorization(){
        return ResponseEntity
                .status(HttpStatus.OK)
                .body("인가성공");
    }
}
