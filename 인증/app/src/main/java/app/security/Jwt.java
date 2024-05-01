package app.security;

import app.exception.type.UnauthorizedException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Reference : https://github.com/auth0/java-jwt/blob/master/EXAMPLES.md
 */
@Getter(value = AccessLevel.PACKAGE)
public class Jwt {
    private final String issuer;
    private final String secret;
    private final long expirySeconds;
    private final Algorithm algorithm;
    private final JWTVerifier jwtVerifier;


    @Builder
    public Jwt(String issuer, String secret, long expirySeconds) {
        this.issuer = issuer;
        this.secret = secret;
        this.expirySeconds = expirySeconds;
        this.algorithm = Algorithm.HMAC512(secret);
        this.jwtVerifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
    }

    public String create(Claims claims) {
        return JWT.create().withIssuer(issuer)
                .withClaim("userId", claims.userId)
                .withClaim("userName", claims.userName)
                .withExpiresAt(Instant.now().plus(expirySeconds, ChronoUnit.SECONDS))
                .sign(algorithm);
    }

    public void verify(String jwt) {
        try {
            DecodedJWT decodedJwt = jwtVerifier.verify(jwt);
//            decodedJwt.getClaim()
        } catch (JWTVerificationException e) {
            throw new UnauthorizedException("유효하지 않은 토큰입니다.");
        }
    }

    public record Claims(Long userId, String userName) {
    }
}
