package app.user;

import app.exception.type.AlreadyExistsException;
import app.exception.type.UnauthenticatedException;
import app.security.Jwt;
import app.security.PasswordEncoder;
import app.security.Refresh;
import app.security.RefreshRepository;
import app.user.request.Login;
import app.user.request.Signup;
import app.user.response.LoginResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final RefreshRepository refreshRepository;
    private final PasswordEncoder passwordEncoder;
    private final Jwt jwt;

    @Transactional
    public void signup(Signup request) {
        Optional<User> userOptional = userRepository.findByEmail(request.email());
        if (userOptional.isPresent()) {
            throw new AlreadyExistsException();
        }
        userRepository.save(User.create(request, passwordEncoder));
    }

    @Transactional
    public LoginResponse login(Login request) {
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new UnauthenticatedException());
        user.login(request.password(), passwordEncoder);
        log.info("[LOGIN] userId = {} ", user.getId());
        return createLoginResponse(user);
    }

    @Transactional
    public LoginResponse refresh(User user) {
        log.info("[REFRESH] userId = {}", user.getId());
        return createLoginResponse(user);
    }

    private LoginResponse createLoginResponse(User user) {
        Refresh refresh = Refresh.builder()
                .userId(user.getId())
                .token(jwt.createRefresh(user))
                .build();
        refreshRepository.save(refresh);
        return new LoginResponse(jwt.create(user), refresh.getToken());
    }
}
