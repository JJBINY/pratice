package appsecurity.user;

import appsecurity.exception.type.AlreadyExistsException;
import appsecurity.exception.type.UnauthenticatedException;
import appsecurity.security.PasswordEncoder;
import appsecurity.security.UserPrincipal;
import appsecurity.security.authentication.AuthenticationProvider;
import appsecurity.user.request.LoginRequest;
import appsecurity.user.request.SignupRequest;
import appsecurity.user.response.LoginResponse;
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
    public void signup(SignupRequest request) {
        Optional<User> userOptional = userRepository.findByEmail(request.email());
        if (userOptional.isPresent()) {
            throw new AlreadyExistsException();
        }
        userRepository.save(User.create(request, passwordEncoder));
    }

    @Transactional
    public LoginResponse login(LoginRequest request) {
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
