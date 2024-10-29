package appsecurity.user;

import appsecurity.common.ApiTestSupport;
import appsecurity.user.controller.dto.SignupRequest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.ResultActions;

import static appsecurity.fixture.UserFixture.aSignupRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Slf4j
@SpringBootTest
@AutoConfigureMockMvc
public class UserApiTest extends ApiTestSupport {

    @Nested
    @DisplayName("회원가입 API")
    class SignUp {

        @Test
        @DisplayName("요청이 성공하면 회원이 생성된다")
        void success() throws Exception {
            // given
            SignupRequest request = aSignupRequest();

            // when
            ResultActions result = callSignupApi(request);

            // then
            result.andExpect(status().isNoContent());
            assertThat(userRepository.findByEmail(request.email()).isPresent()).isTrue();
        }

        @Nested
        @DisplayName("요청이 실패한다")
        class Failure {
            @Test
            @DisplayName("이메일이 중복된 경우")
            void withEmailConflict() throws Exception {
                // given
                SignupRequest request = aSignupRequest();
                callSignupApi(request);

                // when
                ResultActions result = callSignupApi(request);

                // then
                result.andExpectAll(
                        status().isConflict(),
                        jsonPath("$.message").exists());
            }

            @Nested
            @DisplayName("요청 데이터 검증과정에서")
            class WithValidation {

                @ParameterizedTest
                @NullSource
                @ValueSource(strings = {"", "  ", "mail.com", "test", "test@mail"})
                @DisplayName("이메일 양식이 올바르지 않은 경우")
                void wrongEmail(String email) throws Exception {
                    // given
                    SignupRequest request = SignupRequest.builder()
                            .email(email)
                            .build();

                    // when
                    ResultActions result = callSignupApi(request);

                    // then
                    result.andExpectAll(
                            status().isBadRequest(),
                            jsonPath("$.message").exists());
                }

                @ParameterizedTest
                @NullSource
                @ValueSource(strings = {"", "  "})
                @DisplayName("비밀번호 양식이 올바르지 않은 경우")
                void wrongPassword(String password) throws Exception {
                    // given
                    SignupRequest request = SignupRequest.builder()
                            .password(password)
                            .build();

                    // when
                    ResultActions result = callSignupApi(request);

                    // then
                    result.andExpectAll(
                            status().isBadRequest(),
                            jsonPath("$.message").exists());
                }

                @ParameterizedTest
                @NullSource
                @ValueSource(strings = {"", "  "})
                @DisplayName("사용자 이름 양식이 올바르지 않은 경우")
                void wrongName(String name) throws Exception {
                    // given
                    SignupRequest request = SignupRequest.builder()
                            .name(name)
                            .build();

                    // when
                    ResultActions result = callSignupApi(request);

                    // then
                    result.andExpectAll(
                            status().isBadRequest(),
                            jsonPath("$.message").exists());
                }
            }
        }
    }
}
