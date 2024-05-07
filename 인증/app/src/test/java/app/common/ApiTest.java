package app.common;

import app.security.Jwt;
import app.security.JwtConfigProps;
import app.user.UserRepository;
import app.user.request.Login;
import app.user.request.Signup;
import app.user.response.LoginResponse;
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
public class ApiTest {

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


    protected ResultActions callSignupApi(Signup request) throws Exception {
        return mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));
    }

    protected ResultActions callLoginApi(Login request) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));
    }

    protected ResultActions callAuthenticationApi(String token) throws Exception {
        return mockMvc.perform(get("/api/auth/authentication")
                .header(jwtConfigProps.getHeader(), String.join(" ", jwtConfigProps.getScheme(), token)));
    }

    protected ResultActions callAuthorizationApi(String token) throws Exception {
        return mockMvc.perform(get("/api/auth/authorization")
                .header(jwtConfigProps.getHeader(), String.join(" ", jwtConfigProps.getScheme(), token)));
    }

    protected LoginResponse callLoginApiAndGetResponse(Login request) throws Exception {
        ResultActions loginResult = callLoginApi(request);
        String json = loginResult.andReturn().getResponse().getContentAsString();
        return objectMapper.readValue(json, LoginResponse.class);
    }

    protected ResultActions callRefreshApi(String refresh) throws Exception {
         return mockMvc.perform(get("/api/auth/refresh")
                .header(jwtConfigProps.getRefreshHeader(), String.join(" ", jwtConfigProps.getScheme(), refresh)));
    }
}
