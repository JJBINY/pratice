package appsecurity.common;

import appsecurity.security.config.AuthProps;
import appsecurity.security.jwt.JwtProvider;
import appsecurity.security.controller.dto.LoginRequest;
import appsecurity.security.controller.dto.AuthResponse;
import appsecurity.user.controller.dto.SignupRequest;
import appsecurity.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@Slf4j
@SpringBootTest
@AutoConfigureMockMvc
public class ApiTestSupport {

    @Autowired
    protected ObjectMapper objectMapper;

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected UserRepository userRepository;

    @Autowired
    protected AuthProps authProps;

    @Autowired
    protected JwtProvider jwtProvider;

    @Autowired
    CleanUp cleanUp;

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

    protected AuthResponse callLoginApiAndGetResponse(LoginRequest request) throws Exception {
        ResultActions loginResponse = callLoginApi(request);
        String json = loginResponse.andReturn().getResponse().getContentAsString();
        return objectMapper.readValue(json, AuthResponse.class);
    }

    protected ResultActions callRefreshApi(String refresh) throws Exception {
        return mockMvc.perform(get("/api/auth/refresh")
                .header(authProps.refreshHeader, String.join(" ", authProps.scheme, refresh)));
    }

    protected ResultActions callAuthenticationApi(String token) throws Exception {
        return mockMvc.perform(get("/api/users/authentication")
                .header(authProps.header, String.join(" ", authProps.scheme, token)));
    }

    protected ResultActions callAuthorizationApi(String token) throws Exception {
        return mockMvc.perform(get("/api/users/authorization")
                .header(authProps.header, String.join(" ", authProps.scheme, token)));
    }
}
