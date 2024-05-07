package app.security;

import app.exception.type.UnauthenticatedException;
import app.user.Role;
import app.user.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.AccessLevel;
import lombok.Getter;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Random;

/**
 * Reference : https://github.com/auth0/java-jwt/blob/master/EXAMPLES.md
 */
@Getter(value = AccessLevel.PACKAGE)
public class Jwt {
    private final String issuer;
    private final String secret;
    private final long expirySeconds;
    private final long refreshExpirySeconds;
    private final Algorithm algorithm;
    private final JWTVerifier jwtVerifier;
    private final Random randomSalt;

    public Jwt(JwtConfigProps jwtConfigProps) {
        this.issuer = jwtConfigProps.issuer;
        this.secret = jwtConfigProps.secret;
        this.expirySeconds = jwtConfigProps.expirySeconds;
        this.refreshExpirySeconds = jwtConfigProps.refreshExpirySeconds;
        this.algorithm = Algorithm.HMAC512(secret);
        this.jwtVerifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
        this.randomSalt = new Random();
    }

    public String create(User user) {
        return create(user, TokenType.ACCESS, expirySeconds);
    }

    public String createRefresh(User user) {
        return create(user, TokenType.REFRESH, refreshExpirySeconds);
    }

    private String create(User user, TokenType type, long expirySeconds) {
        return JWT.create().withIssuer(issuer)
                .withClaim("userId", user.getId())
                .withClaim("roleName", user.getRole().name())
                .withClaim("type", type.name())
                .withClaim("salt", randomSalt.nextInt())
                .withExpiresAt(Instant.now().plus(expirySeconds, ChronoUnit.SECONDS))
                .sign(algorithm);
    }

    public Claims verify(String jwt) {
        try {
            DecodedJWT decodedJwt = jwtVerifier.verify(jwt);
            Long userId = decodedJwt.getClaim("userId").asLong();
            Role role = Role.valueOf(decodedJwt.getClaim("roleName").asString());
            TokenType type = TokenType.valueOf(decodedJwt.getClaim("type").asString());
            return new Claims(userId, role, type);
        } catch (JWTVerificationException e) {
            throw new UnauthenticatedException("유효하지 않은 토큰입니다.");
        }
    }

    public Claims verify(String jwt, TokenType requiredType) {
        Claims claims = verify(jwt);
        if (claims.type != requiredType) {
            throw new UnauthenticatedException("유효하지 않은 타입의 토큰입니다.");
        }
        return claims;
    }

    public record Claims(Long userId, Role role, TokenType type) {
    }
}
