package app.user;

import app.exception.type.AlreadyExistsException;
import app.exception.type.UnauthenticatedException;
import app.security.Jwt;
import app.security.PasswordEncoder;
import app.user.request.Login;
import app.user.request.Signup;
import app.user.response.LoginResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void signup(Signup request) {
        Optional<User> userOptional = userRepository.findByEmail(request.email());
        if(userOptional.isPresent()){
            throw new AlreadyExistsException();
        }
        userRepository.save(User.create(request, passwordEncoder));
    }

    @Transactional
    public User login(Login request) {
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new UnauthenticatedException());
        user.login(request.password(), passwordEncoder);
        return user;
    }

}
