package appsecurity.user.controller;

import appsecurity.user.service.UserService;
import appsecurity.user.controller.dto.SignupRequest;
import appsecurity.user.service.dto.Signup;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@RequestBody @Valid SignupRequest request) {
        userService.signup(Signup.builder()
                .email(request.email())
                .password(request.password())
                .name(request.name())
                .build());

        return ResponseEntity
                .status(HttpStatus.NO_CONTENT)
                .build();
    }
}
