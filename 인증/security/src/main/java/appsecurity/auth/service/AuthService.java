package appsecurity.auth.service;

import appsecurity.auth.service.dto.Login;
import appsecurity.common.PasswordEncoder;
import appsecurity.auth.exception.UnauthenticatedException;
import appsecurity.auth.UserPrincipal;
import appsecurity.auth.authentication.AuthenticationProvider;
import appsecurity.user.User;
import appsecurity.user.repository.UserRepository;
import appsecurity.auth.service.dto.AuthResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationProvider authenticationProvider;

    @Transactional
    public AuthResult login(Login login) {
        User user = userRepository.findByEmail(login.email())
                .orElseThrow(() -> new UnauthenticatedException("이메일이 존재하지 않습니다."));

        if (!passwordEncoder.matches(login.password(), user.getPassword())) {
            throw new UnauthenticatedException("비밀번호가 일치하지 않습니다.");
        }

        log.info("[LOGIN] userId = {} ", user.getId());
        return createLoginResponse(user);
    }

    @Transactional
    public AuthResult refresh(UserPrincipal userPrincipal) {
        User user = userRepository.findById(userPrincipal.getUserId())
                .orElseThrow(() -> new UnauthenticatedException());

        log.info("[REFRESH] userId = {}", user.getId());
        return createLoginResponse(user);
    }

    private AuthResult createLoginResponse(User user) {
        UserPrincipal userPrincipal = new UserPrincipal(user.getId(), user.getRole());
        String token = authenticationProvider.generateToken(userPrincipal);
        String refresh = authenticationProvider.generateRefresh(userPrincipal);
        return new AuthResult(token, refresh);
    }

    // todo logout
}
