package app.user;

import app.exception.type.AlreadyExistsException;
import app.security.PasswordEncoder;
import app.user.request.Signup;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder = new PasswordEncoder();

    @Transactional
    public void signup(Signup signup) {
        Optional<User> userOptional = userRepository.findByEmail(signup.email());
        if(userOptional.isPresent()){
            throw new AlreadyExistsException();
        }

        String encodedPassword = passwordEncoder.encode(signup.password());

        userRepository.save(User.builder()
                .email(signup.email())
                .password(encodedPassword)
                .name(signup.name())
                .build());
    }
}
