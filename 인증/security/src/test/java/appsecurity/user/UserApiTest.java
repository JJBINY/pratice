package appsecurity.user;

import appsecurity.common.ApiTestSupport;
import appsecurity.security.authorization.Role;
import appsecurity.security.controller.dto.LoginRequest;
import appsecurity.security.controller.dto.LoginResponse;
import appsecurity.user.controller.dto.SignupRequest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.ResultActions;

import java.util.Optional;
import java.util.stream.Stream;

import static appsecurity.fixture.UserFixture.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.not;
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

    @Test
    @DisplayName("로그인 성공")
    void loginSuccess() throws Exception {
        // given
        callSignupApi(aSignupRequest());
        LoginRequest request = aLoginRequest();

        // when
        ResultActions result = callLoginApi(request);

        // then
        result.andDo(print())
                .andExpectAll(
                        status().isOk(),
                        jsonPath("$.token").exists(),
                        jsonPath("$.token").isString(),
                        jsonPath("$.refresh").exists(),
                        jsonPath("$.refresh").isString());
    }

    static Stream<Arguments> loginFailureWithWrongData() {
        SignupRequest signupRequest = aSignupRequest();
        String email = signupRequest.email();
        String password = signupRequest.password();
        return Stream.of(
                Arguments.of("wrong" + email, password),
                Arguments.of(email, "wrong" + password)
        );
    }

    @ParameterizedTest
    @MethodSource
    @DisplayName("로그인 실패 : 이메일 또는 비밀번호가 올바르지 않음")
    void loginFailureWithWrongData(String email, String password) throws Exception {
        // given
        callSignupApi(aSignupRequest());
        LoginRequest request = aLoginRequestBuilder()
                .email(email)
                .password(password)
                .build();

        // when
        ResultActions result = callLoginApi(request);

        // then
        result.andDo(print())
                .andExpectAll(
                        status().isUnauthorized(),
                        jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("인증 성공")
    void authenticationSuccess() throws Exception {
        // given
        callSignupApi(aSignupRequest());
        String token = callLoginApiAndGetResponse(aLoginRequest()).token();

        // when
        ResultActions result = callAuthenticationApi(token);

        // then
        result.andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("인증 실패")
    void authenticationFailure() throws Exception {
        // given
        String token = "wrong_token";

        // when
        ResultActions result = callAuthenticationApi(token);

        // then
        result.andDo(print())
                .andExpectAll(
                        status().isUnauthorized(),
                        jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("인가 성공")
    void authorizationSuccess() throws Exception {
        // given
        callSignupApi(aSignupRequest());
        User user = userRepository.findByEmail(aSignupRequest().email()).get();
        user.changeRole(Role.ADMIN);
        userRepository.save(user);
        String token = callLoginApiAndGetResponse(aLoginRequest()).token();

        // when
        ResultActions result = callAuthorizationApi(token);

        // then
        result.andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("인가 실패")
    void authorizationFailure() throws Exception {
        // given
        callSignupApi(aSignupRequest());
        String token = callLoginApiAndGetResponse(aLoginRequest()).token();

        // when
        ResultActions result = callAuthorizationApi(token);

        // then
        result.andDo(print())
                .andExpectAll(
                        status().isForbidden(),
                        jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("리프래시 성공 : 새로운 토큰들을 발급받는다.")
    void refreshSuccess() throws Exception {
        // given
        callSignupApi(aSignupRequest());
        LoginResponse loginResponse = callLoginApiAndGetResponse(aLoginRequest());
        String oldToken = loginResponse.token();
        String oldRefresh = loginResponse.refresh();

        // when
        ResultActions result = callRefreshApi(oldRefresh);

        // then
        result.andDo(print())
                .andExpectAll(
                        status().isOk(),
                        jsonPath("$.token").exists(),
                        jsonPath("$.token").isString(),
                        jsonPath("$.token").value(not(oldToken)),
                        jsonPath("$.refresh").exists(),
                        jsonPath("$.refresh").isString(),
                        jsonPath("$.refresh").value(not(oldRefresh)));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"wrong_refresh_token", "", "  "})
    @DisplayName("리프래시 실패 : 유효하지 않은 토큰 사용")
    void refreshFailure(Object source) throws Exception {
        // given
        String refresh = (String) source;

        // when
        ResultActions result = callRefreshApi(refresh);

        // then
        result.andDo(print())
                .andExpectAll(
                        status().isUnauthorized(),
                        jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("리프래시 실패 : 가장 최근에 갱신된 토큰을 사용해야 한다.")
    void refreshFailureWithOldToken() throws Exception {
        // given
        callSignupApi(aSignupRequest());
        String oldRefresh = callLoginApiAndGetResponse(aLoginRequest()).refresh();
        callLoginApiAndGetResponse(aLoginRequest()).refresh();

        // when
        ResultActions result = callRefreshApi(oldRefresh);

        // then
        result.andDo(print())
                .andExpectAll(
                        status().isUnauthorized(),
                        jsonPath("$.message").exists());
    }
}
