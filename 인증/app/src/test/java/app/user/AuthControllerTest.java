package app.user;

import app.common.ApiTest;
import app.user.request.Login;
import app.user.request.Signup;
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

import static app.fixture.UserFixture.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Slf4j
@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerTest extends ApiTest {

    @Test
    @DisplayName("회원가입 성공 테스트")
    void signupSuccess() throws Exception {
        // given
        Signup request = aSignupRequest();

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
    @DisplayName("회원가입 실패 테스트 : 이메일 중복")
    void signupFailureWithEmailConflict() throws Exception {
        // given
        Signup request = aSignupRequest();
        callSignupApi(request);

        // when
        ResultActions result = callSignupApi(request);

        // then
        result.andDo(print())
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").exists());
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
    @DisplayName("회원가입 실패 테스트 : 잘못된 입력 데이터")
    void signupFailureWithWrongData(String email, String password, String name) throws Exception {
        // given
        Signup request = Signup.builder()
                .email(email)
                .password(password)
                .name(name)
                .build();

        // when
        ResultActions result = callSignupApi(request);

        // then
        result.andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("로그인 성공 테스트")
    void loginSuccess() throws Exception {
        // given
        callSignupApi(aSignupRequest());
        Login request = aLoginRequest();

        // when
        ResultActions result = callLoginApi(request);

        // then
        result.andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.token").isString());
    }

    static Stream<Arguments> loginFailureWithWrongData() {
        Signup signup = aSignupRequest();
        String email = signup.email();
        String password = signup.password();
        return Stream.of(
                Arguments.of("wrong" + email, password),
                Arguments.of(email, "wrong" + password)
        );
    }

    @ParameterizedTest
    @MethodSource
    @DisplayName("로그인 실패 테스트 : 이메일 또는 비밀번호가 올바르지 않음")
    void loginFailureWithWrongData(String email, String password) throws Exception {
        // given
        callSignupApi(aSignupRequest());
        Login request = aLoginRequestBuilder()
                .email(email)
                .password(password)
                .build();

        // when
        ResultActions result = callLoginApi(request);

        // then
        result.andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("인증 성공 테스트")
    void authenticationSuccess() throws Exception {
        // given
        callSignupApi(aSignupRequest());
        String token = callLoginApiAndGetToken(aLoginRequest());

        // when
        ResultActions result = callAuthenticationApi(token);

        // then
        result.andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("인증 실패 테스트")
    void authenticationFailure() throws Exception {
        // given
        String token = "wrong_token";

        // when
        ResultActions result = callAuthenticationApi(token);

        // then
        result.andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("인가 성공 테스트")
    void authorizationSuccess() throws Exception {
        // given
        callSignupApi(aSignupRequest());
        User user = userRepository.findByEmail(aSignupRequest().email()).get();
        user.changeRole(Role.ADMIN);
        userRepository.save(user);
        String token = callLoginApiAndGetToken(aLoginRequest());

        // when
        ResultActions result = callAuthorizationApi(token);

        // then
        result.andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("인가 실패 테스트")
    void authorizationFailure() throws Exception {
        // given
        callSignupApi(aSignupRequest());
        String token = callLoginApiAndGetToken(aLoginRequest());

        // when
        ResultActions result = callAuthorizationApi(token);

        // then
        result.andDo(print())
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").exists());
    }
}
