package appsecurity.user.service;

import appsecurity.user.service.dto.Signup;
import appsecurity.common.exception.AlreadyExistsException;
import appsecurity.common.PasswordEncoder;
import appsecurity.user.User;
import appsecurity.user.repository.UserRepository;
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
}
