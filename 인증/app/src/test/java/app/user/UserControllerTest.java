package app.user;

import app.user.request.Signup;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Slf4j
@SpringBootTest
@AutoConfigureMockMvc
public class UserControllerTest {

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    MockMvc mockMvc;

    @Autowired
    UserRepository userRepository;

    @BeforeEach
    void beforeEach() {
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("회원가입 성공 테스트")
    void signupSuccess() throws Exception {
        // given
        Signup request = Signup.builder()
                .email("test@mail.com")
                .password("1234")
                .name("테스트유저")
                .build();

        // when
        ResultActions result = signup(request);

        // then
        result.andDo(print())
                .andExpect(status().isNoContent());

        Optional<User> userOptional = userRepository.findByEmail(request.email());
        assertThat(userOptional.isPresent()).isTrue();
        assertThat(userOptional.get().getPassword()).isNotEqualTo(request.password());
        log.info(userOptional.toString());
    }

    @Test
    @DisplayName("회원가입 실패 테스트 : 이메일 중복")
    void signupFailureWithEmailConflict() throws Exception {
        // given
        Signup request = Signup.builder()
                .email("test@mail.com")
                .password("1234")
                .name("테스트유저")
                .build();
        signup(request);

        // when
        ResultActions result = signup(request);

        // then
        result.andDo(print())
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").exists());
    }


    static Stream<Arguments> signupFailureWithWrongData(){
        return Stream.of(
                Arguments.of("testmail.com", "1234", "name"),
                Arguments.of("", "1234", "name"),
                Arguments.of("test@mail.com", "", "name"),
                Arguments.of("test@mail.com", "1234", ""),
                Arguments.of("test", "1234", "")
        );
    }
    @ParameterizedTest
    @MethodSource
    @DisplayName("회원가입 실패 테스트 : 잘못된 입력 데이터")
    void signupFailureWithWrongData(String email, String password, String name) throws Exception {
        // given
        Signup request = Signup.builder()
                .email(email)
                .password(password)
                .name(name)
                .build();

        // when
        ResultActions result = signup(request);

        // then
        result.andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    private ResultActions signup(Signup request) throws Exception {
        ResultActions result = mockMvc.perform(post("/api/users/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));
        return result;
    }
}
