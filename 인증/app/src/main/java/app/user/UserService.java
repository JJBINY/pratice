package app.user;

import app.exception.type.AlreadyExistsException;
import app.exception.type.UnauthenticatedException;
import app.security.PasswordEncoder;
import app.security.UserPrincipal;
import app.security.authentication.AuthenticationProvider;
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
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationProvider authenticationProvider;

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
    public LoginResponse refresh(UserPrincipal userPrincipal) {
        User user = userRepository.findById(userPrincipal.getUserId())
                .orElseThrow(() -> new UnauthenticatedException());
        log.info("[REFRESH] userId = {}", user.getId());
        return createLoginResponse(user);
    }

    private LoginResponse createLoginResponse(User user) {
        UserPrincipal userPrincipal = new UserPrincipal(user.getId(), user.getRole());
        String token = authenticationProvider.createToken(userPrincipal);
        String refresh = authenticationProvider.createRefresh(userPrincipal);
        return new LoginResponse(token, refresh);
    }
}
