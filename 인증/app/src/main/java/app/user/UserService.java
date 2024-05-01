package app.user;

import app.exception.type.AlreadyExistsException;
import app.exception.type.NotFoundException;
import app.exception.type.UnauthorizedException;
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
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final Jwt jwt;

    @Transactional
    public void signup(Signup request) {
        Optional<User> userOptional = userRepository.findByEmail(request.email());
        if(userOptional.isPresent()){
            throw new AlreadyExistsException();
        }

        String encodedPassword = passwordEncoder.encode(request.password());

        userRepository.save(User.builder()
                .email(request.email())
                .password(encodedPassword)
                .name(request.name())
                .build());
    }

    @Transactional
    public LoginResponse login(Login request) {
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new UnauthorizedException());
        if(!passwordEncoder.matches(request.password(), user.getPassword())){
            throw new UnauthorizedException();
        }

        String token = jwt.create(new Jwt.Claims(user.getId(), user.getName()));

        return new LoginResponse(user.getId(), token);
    }

}
