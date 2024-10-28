package appsecurity.common;

import appsecurity.security.authentication.Jwt;
import appsecurity.security.authentication.JwtConfigProps;
import appsecurity.user.UserRepository;
import appsecurity.user.request.LoginRequest;
import appsecurity.user.request.SignupRequest;
import appsecurity.user.response.LoginResponse;
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
    protected JwtConfigProps jwtConfigProps;

    @Autowired
    protected Jwt jwt;

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
        return mockMvc.perform(post("/api/users/login")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));
    }

    protected ResultActions callAuthenticationApi(String token) throws Exception {
        return mockMvc.perform(get("/api/users/authentication")
                .header(jwtConfigProps.getHeader(), String.join(" ", jwtConfigProps.getScheme(), token)));
    }

    protected ResultActions callAuthorizationApi(String token) throws Exception {
        return mockMvc.perform(get("/api/users/authorization")
                .header(jwtConfigProps.getHeader(), String.join(" ", jwtConfigProps.getScheme(), token)));
    }

    protected LoginResponse callLoginApiAndGetResponse(LoginRequest request) throws Exception {
        ResultActions loginResult = callLoginApi(request);
        String json = loginResult.andReturn().getResponse().getContentAsString();
        return objectMapper.readValue(json, LoginResponse.class);
    }

    protected ResultActions callRefreshApi(String refresh) throws Exception {
         return mockMvc.perform(get("/api/users/refresh")
                .header(jwtConfigProps.getRefreshHeader(), String.join(" ", jwtConfigProps.getScheme(), refresh)));
    }
}
