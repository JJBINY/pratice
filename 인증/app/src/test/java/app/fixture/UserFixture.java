package app.fixture;

import app.user.Role;
import app.user.User;
import app.user.request.Login;
import app.user.request.Signup;

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

    public static Signup.SignupBuilder aSignupRequestBuilder(){
        return Signup.builder()
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .name(DEFAULT_NAME);
    }

    public static Signup aSignupRequest(){
        return aSignupRequestBuilder().build();
    }

    public static Login.LoginBuilder aLoginRequestBuilder(){
        return Login.builder()
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD);
    }

    public static Login aLoginRequest(){
        return aLoginRequestBuilder().build();
    }
}
