package appsecurity.common;

import appsecurity.auth.blacklist.BlackedTokenRepository;
import appsecurity.auth.config.AuthProps;
import appsecurity.auth.controller.dto.AuthResponse;
import appsecurity.auth.controller.dto.LoginRequest;
import appsecurity.user.controller.dto.SignupRequest;
import appsecurity.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@Slf4j
@SpringBootTest
@AutoConfigureMockMvc
public class ApiTestSupport {

    @Autowired
    private CleanUp cleanUp;

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected ObjectMapper objectMapper;

    @Autowired
    protected AuthProps authProps;

    @Autowired
    protected UserRepository userRepository;

    @Autowired
    protected BlackedTokenRepository blackedTokenRepository;


    @BeforeEach
    void beforeEach() {
        cleanUp.all();
    }


    protected ResultActions callSignupApi(SignupRequest request) throws Exception {
        return mockMvc.perform(post("/api/users/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));
    }

    protected ResultActions callLoginApi(LoginRequest request) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));
    }

    protected AuthResult callLoginApiAndGetAuthResults(LoginRequest request) throws Exception {
        return getAuthResult(callLoginApi(request));
    }

    protected AuthResult getAuthResult(ResultActions result) throws Exception {
        MockHttpServletResponse response = result.andReturn().getResponse();
        var json = response.getContentAsString();
        var accessToken = objectMapper.readValue(json, AuthResponse.class).accessToken();
        var refreshToken = response.getCookie("refreshToken").getValue();
        return new AuthResult(accessToken, refreshToken);
    }

    protected ResultActions callRefreshApi(String refreshToken) throws Exception {
        return mockMvc.perform(post("/api/auth/refresh")
                .cookie(new Cookie("refreshToken", refreshToken)));
    }

    protected ResultActions callLogoutApi(String accessToken, String refreshToken) throws Exception {
        return mockMvc.perform(post("/api/auth/logout")
                .header(authProps.header, String.join(" ", authProps.scheme, accessToken))
                .cookie(new Cookie("refreshToken", refreshToken)));
    }

    protected ResultActions callAuthenticationApi(String accessToken) throws Exception {
        return mockMvc.perform(get("/api/auth/authentication")
                .header(authProps.header, String.join(" ", authProps.scheme, accessToken)));
    }

    protected ResultActions callAuthorizationApi(String accessToken) throws Exception {
        return mockMvc.perform(get("/api/auth/authorization")
                .header(authProps.header, String.join(" ", authProps.scheme, accessToken)));
    }

    protected record AuthResult(String accessToken, String refreshToken) {
    }
}
