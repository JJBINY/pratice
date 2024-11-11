package appsecurity.auth.jwt;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;

import static appsecurity.auth.jwt.JwtClaimName.*;
import static appsecurity.auth.jwt.JwtClaimName.ROLES;

@Component
@RequiredArgsConstructor
public class JwtValidator {

    private final JwtProvider jwtProvider;

    public JwtClaims validate(String jwt) throws JwtValidationException {
        return parseClaims(decode(jwt));
    }

    private DecodedJWT decode(String jwt) throws JwtValidationException {
        try {
            return jwtProvider.getVerifier().verify(jwt);
        } catch (JWTVerificationException e) {
            if(e instanceof TokenExpiredException){
                throw new JwtValidationException("만료된 토큰입니다");
            }else {
                throw new JwtValidationException();
            }
        }
    }

    private JwtClaims parseClaims(DecodedJWT decodedJWT){
        Map<String, Claim> claims = decodedJWT.getClaims();
        var tokenId = claims.get(TOKEN_ID.claim()).asLong();
        var userId = claims.get(USER_ID.claim()).asLong();
        var type = JwtType.valueOf(claims.get(TYPE.claim()).asString());
        var roles = claims.get(ROLES.claim()).asList(String.class);
        var expiresAt = decodedJWT.getExpiresAtAsInstant();
        return new JwtClaims(tokenId, userId, type, roles, expiresAt);
    }
}
