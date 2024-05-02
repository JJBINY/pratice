package app.user;

import app.CleanUp;
import app.security.JwtConfigProps;
import app.user.request.Login;
import app.user.request.Signup;
import app.user.response.LoginResponse;
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

import static app.fixture.UserFixture.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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

    @Autowired
    JwtConfigProps jwtConfigProps;

    @Autowired
    CleanUp cleanUp;

    @BeforeEach
    void beforeEach() {
        cleanUp.all();
    }

    @Test
    @DisplayName("회원가입 성공 테스트")
    void signupSuccess() throws Exception {
        // given
        Signup request = aSignup();

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
        Signup request = aSignup();
        signup(request);

        // when
        ResultActions result = signup(request);

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
        ResultActions result = signup(request);

        // then
        result.andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("로그인 성공 테스트")
    void loginSuccess() throws Exception {
        // given
        Signup signup = aSignup();
        signup(signup);
        Login request = aLogin();

        // when
        ResultActions result = login(request);

        // then
        result.andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.token").isString())
                .andExpect(jsonPath("$.userId").exists())
                .andExpect(jsonPath("$.userId").isNumber());
    }

    static Stream<Arguments> loginFailureWithWrongData() {
        Signup signup = aSignup();
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
        signup(aSignup());
        Login request = aLoginBuilder()
                .email(email)
                .password(password)
                .build();

        // when
        ResultActions result = login(request);

        // then
        result.andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("인증 성공 테스트")
    void authenticationSuccess() throws Exception {
        // given
        signup(aSignup());
        String json = login(aLogin()).andReturn().getResponse().getContentAsString();
        LoginResponse loginResponse = objectMapper.readValue(json, LoginResponse.class);
        String token = loginResponse.token();

        // when
        ResultActions result = authentication(token);

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
        ResultActions result = authentication(token);

        // then
        result.andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("인가 성공 테스트")
    void authorizationSuccess() throws Exception {
        // given
        signup(aSignup());
        User user = userRepository.findByEmail(aSignup().email()).get();
        user.changeRole(Role.ADMIN);
        userRepository.save(user);
        String token = loginAndGetToken(aLogin());

        // when
        ResultActions result = authorization(token);

        // then
        result.andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("인가 실패 테스트")
    void authorizationFailure() throws Exception {
        // given
        signup(aSignup());
        String token = loginAndGetToken(aLogin());

        // when
        ResultActions result = authorization(token);

        // then
        result.andDo(print())
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").exists());
    }

    private ResultActions signup(Signup request) throws Exception {
        return mockMvc.perform(post("/api/users/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));
    }

    private ResultActions login(Login request) throws Exception {
        return mockMvc.perform(post("/api/users/login")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));
    }

    private ResultActions authentication(String token) throws Exception{
        return mockMvc.perform(get("/api/users/authentication")
                .header(jwtConfigProps.getHeader(), token));
    }

    private ResultActions authorization(String token) throws Exception{
        return mockMvc.perform(get("/api/users/authorization")
                .header(jwtConfigProps.getHeader(), token));
    }

    private String loginAndGetToken(Login request) throws Exception {
        ResultActions loginResult = login(request);
        String json = loginResult.andReturn().getResponse().getContentAsString();
        LoginResponse loginResponse = objectMapper.readValue(json, LoginResponse.class);
        return loginResponse.token();
    }
}
