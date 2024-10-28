package appsecurity.user.service;

import appsecurity.exception.type.AlreadyExistsException;
import appsecurity.exception.type.UnauthenticatedException;
import appsecurity.security.PasswordEncoder;
import appsecurity.security.UserPrincipal;
import appsecurity.security.authentication.AuthenticationProvider;
import appsecurity.user.User;
import appsecurity.user.repository.UserRepository;
import appsecurity.user.service.dto.Login;
import appsecurity.user.service.dto.LoginResult;
import appsecurity.user.service.dto.Signup;
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
    public void signup(Signup signup) {
        Optional<User> userOptional = userRepository.findByEmail(signup.email());
        if (userOptional.isPresent()) {
            throw new AlreadyExistsException();
        }

        userRepository.save(User.builder()
                .email(signup.email())
                .password(passwordEncoder.encode(signup.password()))
                .name(signup.name())
                .build());
    }

    @Transactional
    public LoginResult login(Login login) {
        User user = userRepository.findByEmail(login.email())
                .orElseThrow(() -> new UnauthenticatedException("이메일이 존재하지 않습니다."));

        if (!passwordEncoder.matches(login.password(), user.getPassword())) {
            throw new UnauthenticatedException("비밀번호가 일치하지 않습니다.");
        }

        log.info("[LOGIN] userId = {} ", user.getId());
        return createLoginResponse(user);
    }

    @Transactional
    public LoginResult refresh(UserPrincipal userPrincipal) {
        User user = userRepository.findById(userPrincipal.getUserId())
                .orElseThrow(() -> new UnauthenticatedException());

        log.info("[REFRESH] userId = {}", user.getId());
        return createLoginResponse(user);
    }

    private LoginResult createLoginResponse(User user) {
        UserPrincipal userPrincipal = new UserPrincipal(user.getId(), user.getRole());
        String token = authenticationProvider.createToken(userPrincipal);
        String refresh = authenticationProvider.createRefresh(userPrincipal);
        return new LoginResult(token, refresh);
    }
}
