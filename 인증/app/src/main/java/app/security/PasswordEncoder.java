package app.security;

import org.mindrot.jbcrypt.BCrypt;

public class PasswordEncoder {

    public String encode(String password){
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }
    public boolean matches(String plain, String encrypted){
        return BCrypt.checkpw(plain, encrypted);
    }
}
