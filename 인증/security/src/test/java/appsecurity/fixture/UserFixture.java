package appsecurity.fixture;

import appsecurity.security.authorization.Role;
import appsecurity.user.User;
import appsecurity.user.controller.dto.LoginRequest;
import appsecurity.user.controller.dto.SignupRequest;

public class UserFixture extends User{

    public static String DEFAULT_EMAIL = "test@mail.com";
    public static String DEFAULT_PASSWORD = "password";
    public static String DEFAULT_NAME = "username";
    public static UserBuilder anUserBuilder() {
        return User.builder()
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .name(DEFAULT_NAME)
                .role(Role.USER);
    }

    public static User anUser(){
        return UserFixture.anUserBuilder().build();
    }

    public static SignupRequest.SignupRequestBuilder aSignupRequestBuilder(){
        return SignupRequest.builder()
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .name(DEFAULT_NAME);
    }

    public static SignupRequest aSignupRequest(){
        return aSignupRequestBuilder().build();
    }

    public static LoginRequest.LoginRequestBuilder aLoginRequestBuilder(){
        return LoginRequest.builder()
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD);
    }

    public static LoginRequest aLoginRequest(){
        return aLoginRequestBuilder().build();
    }
}
