package appsecurity.common;

import appsecurity.auth.config.AuthProps;
import appsecurity.auth.jwt.JwtProvider;
import appsecurity.auth.controller.dto.LoginRequest;
import appsecurity.auth.controller.dto.AuthResponse;
import appsecurity.user.controller.dto.SignupRequest;
import appsecurity.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.Before;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MockMvcBuilder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.filter.CharacterEncodingFilter;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

@Slf4j
@SpringBootTest
//@AutoConfigureMockMvc
public class ApiTestSupport {

    @Autowired
    protected ObjectMapper objectMapper;

    @Autowired
    WebApplicationContext ctx;

//    @Autowired
    protected MockMvc mockMvc;

    @BeforeEach
    public void setUp(){
        mockMvc = MockMvcBuilders.webAppContextSetup(ctx)
                .alwaysDo(print())
                .addFilters(new CharacterEncodingFilter("UTF-8", true))
                .build();
    }


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
