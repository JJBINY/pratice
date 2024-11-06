package appsecurity.auth.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static appsecurity.auth.jwt.JwtType.ACCESS;
import static appsecurity.auth.jwt.JwtType.REFRESH;
import static appsecurity.auth.jwt.JwtClaims.*;

/**
 * Reference : https://github.com/auth0/java-jwt/blob/master/EXAMPLES.md
 */
@Component
public class JwtProvider {
    private final String issuer;
    private final String secret;
    private final Map<JwtType, Long> expirySecondsMap;
    private final Algorithm algorithm;
    private final JWTVerifier jwtVerifier;
    private final Random randomSalt;

    public JwtProvider(JwtConfigProps jwtConfigProps) {
        this.issuer = jwtConfigProps.issuer;
        this.secret = jwtConfigProps.secret;
        this.expirySecondsMap = Map.of(
                ACCESS, jwtConfigProps.expirySeconds,
                REFRESH, jwtConfigProps.refreshExpirySeconds);
        this.algorithm = Algorithm.HMAC512(secret);
        this.jwtVerifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
        this.randomSalt = new Random();
    }

    public String createToken(Long userId, List<String> roles, JwtType type) {
        return createToken(userId, roles, type, expirySecondsMap.get(type));
    }

    private String createToken(Long userId, List<String> roles, JwtType type, long expirySeconds) { //todo authUser, Role 등 외부 의존성 JwtAuthenticationProvider로 빼내기

        return JWT.create().withIssuer(issuer)
                .withClaim(USER_ID.claim(), userId)
                .withClaim(ROLES.claim(), roles)
                .withClaim(TYPE.claim(), type.name())
                .withClaim(SALT.claim(), randomSalt.nextInt())
                .withExpiresAt(Instant.now().plus(expirySeconds, ChronoUnit.SECONDS))
                .sign(algorithm);
    }

    public Claims validate(String jwt, JwtType requiredType) throws JwtValidationException {
        Claims claims = validate(jwt);
        if (claims.type != requiredType) {
            throw new JwtValidationException("유효하지 않은 타입의 토큰입니다.");
        }
        return claims;
    }

    public Claims validate(String jwt) throws JwtValidationException {
        Map<String, Claim> claims = decode(jwt).getClaims();

        Long userId = claims.get(USER_ID.claim()).asLong();
        JwtType type = JwtType.valueOf(claims.get(TYPE.claim()).asString());
        List<String> roles = claims.get(ROLES.claim()).asList(String.class);
        return new Claims(userId, type, roles);

    }

    private DecodedJWT decode(String jwt) throws JwtValidationException {
        try {
            return jwtVerifier.verify(jwt);
        } catch (JWTVerificationException e) {
            throw new JwtValidationException();
        }
    }

    public record Claims(Long userId, JwtType type, List<String> roles) {
    }
}
