package appsecurity.auth;

import appsecurity.auth.controller.dto.AuthResponse;
import appsecurity.auth.controller.dto.LoginRequest;
import appsecurity.common.ApiTestSupport;
import appsecurity.user.User;
import appsecurity.user.controller.dto.SignupRequest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.ResultActions;

import java.util.stream.Stream;

import static appsecurity.fixture.UserFixture.*;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Slf4j
@SpringBootTest
@AutoConfigureMockMvc
public class AuthApiTest extends ApiTestSupport {

    @Nested
    @DisplayName("로그인 API")
    class Login {
        @Test
        @DisplayName("요청이 성공하면 AccessToken과 RefreshToken이 발급된다")
        void success() throws Exception {
            // given
            callSignupApi(aSignupRequest());
            LoginRequest request = aLoginRequest();

            // when
            ResultActions result = callLoginApi(request);

            // then
            result.andExpectAll(
                    status().isOk(),
                    jsonPath("$.accessToken").exists(),
                    jsonPath("$.accessToken").isString(),
                    jsonPath("$.refreshToken").exists(),
                    jsonPath("$.refreshToken").isString());
        }

        @Nested
        @DisplayName("요청이 실패한다")
        class Failure {
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
            @DisplayName("이메일 또는 비밀번호가 일치하는 유저가 없는 경우")
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
                result.andExpectAll(
                        status().isUnauthorized(),
                        jsonPath("$.message").exists());
            }
        }
    }

    @Nested
    @DisplayName("엑세스 토큰 리프래시 API")
    class Refresh {
        @Test
        @DisplayName("요청이 성공하면 새로운 AccessToken과 RefreshToken을 발급받는다")
        void refreshSuccess() throws Exception {
            // given
            callSignupApi(aSignupRequest());
            AuthResponse authResponse = callLoginApiAndGetResponse(aLoginRequest());
            String oldToken = authResponse.accessToken();
            String oldRefresh = authResponse.refreshToken();

            // when
            ResultActions result = callRefreshApi(oldRefresh);

            // then
            result.andExpectAll(
                    status().isOk(),
                    jsonPath("$.accessToken").exists(),
                    jsonPath("$.accessToken").isString(),
                    jsonPath("$.accessToken").value(not(oldToken)),
                    jsonPath("$.refreshToken").exists(),
                    jsonPath("$.refreshToken").isString(),
                    jsonPath("$.refreshToken").value(not(oldRefresh)));
        }

        @Nested
        @DisplayName("요청이 실패한다")
        class Failure {
            @ParameterizedTest
            @NullSource
            @ValueSource(strings = {"wrong_refresh_token", "", "  "})
            @DisplayName("유효하지 않은 RefreshToken을 사용한 경우")
            void refreshFailure(Object source) throws Exception {
                // given
                String refresh = (String) source;

                // when
                ResultActions result = callRefreshApi(refresh);

                // then
                result.andExpectAll(
                        status().isUnauthorized(),
                        jsonPath("$.message").exists());
            }

            @Test
            @DisplayName("가장 최근에 발급받은 RefreshToken이 아닌 다른 토큰을 사용한 경우")
            void refreshFailureWithOldToken() throws Exception {
                // given
                callSignupApi(aSignupRequest());
                String oldRefresh = callLoginApiAndGetResponse(aLoginRequest()).refreshToken();
                callLoginApiAndGetResponse(aLoginRequest()).refreshToken();

                // when
                ResultActions result = callRefreshApi(oldRefresh);

                // then
                result.andExpectAll(
                        status().isUnauthorized(),
                        jsonPath("$.message").exists());
            }
        }

    }

    @Test
    @DisplayName("인증 성공")
    void authenticationSuccess() throws Exception {
        // given
        callSignupApi(aSignupRequest());
        String accessToken = callLoginApiAndGetResponse(aLoginRequest()).accessToken();

        // when
        ResultActions result = callAuthenticationApi(accessToken);

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
        String token = callLoginApiAndGetResponse(aLoginRequest()).accessToken();

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
        String token = callLoginApiAndGetResponse(aLoginRequest()).accessToken();

        // when
        ResultActions result = callAuthorizationApi(token);

        // then
        result.andDo(print())
                .andExpectAll(
                        status().isForbidden(),
                        jsonPath("$.message").exists());
    }
}
