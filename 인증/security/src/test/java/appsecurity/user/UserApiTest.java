package appsecurity.user;

import appsecurity.common.ApiTestSupport;
import appsecurity.user.controller.dto.SignupRequest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.ResultActions;

import java.util.Optional;
import java.util.stream.Stream;

import static appsecurity.fixture.UserFixture.aSignupRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Slf4j
@SpringBootTest
@AutoConfigureMockMvc
public class UserApiTest extends ApiTestSupport {

    @Test
    @DisplayName("회원가입 성공")
    void signupSuccess() throws Exception {
        // given
        SignupRequest request = aSignupRequest();

        // when
        ResultActions result = callSignupApi(request);

        // then
        result.andDo(print())
                .andExpect(status().isNoContent());

        Optional<User> userOptional = userRepository.findByEmail(request.email());
        assertThat(userOptional.isPresent()).isTrue();
        assertThat(userOptional.get().getPassword()).isNotEqualTo(request.password());
        log.info(userOptional.toString());
    }

    @Test
    @DisplayName("회원가입 실패 : 이메일 중복")
    void signupFailureWithEmailConflict() throws Exception {
        // given
        SignupRequest request = aSignupRequest();
        callSignupApi(request);

        // when
        ResultActions result = callSignupApi(request);

        // then
        result.andDo(print())
                .andExpectAll(
                        status().isConflict(),
                        jsonPath("$.message").exists());
    }


    static Stream<Arguments> signupFailureWithWrongData() {
        return Stream.of(
                Arguments.of("testmail.com", "password", "name"),
                Arguments.of("", "password", "name"),
                Arguments.of("test@mail.com", "", "name"),
                Arguments.of("test@mail.com", "password", ""),
                Arguments.of("test", "password", ""),
                Arguments.of(null, "password", "name"),
                Arguments.of("test@mail.com", null, "name"),
                Arguments.of("test@mail.com", "password", null),
                Arguments.of("test", "password", null)
        );
    }

    @ParameterizedTest
    @MethodSource
    @DisplayName("회원가입 실패 : 잘못된 입력 데이터")
    void signupFailureWithWrongData(String email, String password, String name) throws Exception {
        // given
        SignupRequest request = SignupRequest.builder()
                .email(email)
                .password(password)
                .name(name)
                .build();

        // when
        ResultActions result = callSignupApi(request);

        // then
        result.andDo(print())
                .andExpectAll(
                        status().isBadRequest(),
                        jsonPath("$.message").exists());
    }
}
