package app.fixture;

import app.user.User;
import app.user.User.UserBuilder;
import app.user.request.Login;
import app.user.request.Signup;

public class UserFixture {

    public static String DEFAULT_EMAIL = "test@mail.com";
    public static String DEFAULT_PASSWORD = "password";
    public static String DEFAULT_NAME = "username";
    public static UserBuilder anUserBuilder() {
        return User.builder()
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .name(DEFAULT_NAME);

    }

    public static User anUser(){
        return UserFixture.anUserBuilder().build();
    }

    public static Signup.SignupBuilder aSignupBuilder(){
        return Signup.builder()
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .name(DEFAULT_NAME);
    }

    public static Signup aSignup(){
        return aSignupBuilder().build();
    }

    public static Login.LoginBuilder aLoginBuilder(){
        return Login.builder()
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD);
    }

    public static Login aLogin(){
        return aLoginBuilder().build();
    }
}
