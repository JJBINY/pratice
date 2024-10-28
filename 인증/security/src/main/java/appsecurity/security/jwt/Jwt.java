package appsecurity.security.jwt;

import appsecurity.exception.type.UnauthenticatedException;
import appsecurity.security.UserPrincipal;
import appsecurity.security.authentication.TokenType;
import appsecurity.security.authorization.Role;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.AccessLevel;
import lombok.Getter;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Random;

import static appsecurity.security.authentication.TokenType.ACCESS;
import static appsecurity.security.authentication.TokenType.REFRESH;

/**
 * Reference : https://github.com/auth0/java-jwt/blob/master/EXAMPLES.md
 */
@Component
@Getter(value = AccessLevel.PACKAGE)
public class Jwt {
    private final String issuer;
    private final String secret;
    private final Map<TokenType, Long> expirySecondsMap;
    private final Algorithm algorithm;
    private final JWTVerifier jwtVerifier;
    private final Random randomSalt;

    public Jwt(JwtConfigProps jwtConfigProps) {
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

    public String create(UserPrincipal userPrincipal, TokenType type) {
        return create(userPrincipal, type, expirySecondsMap.get(type));
    }

    private String create(UserPrincipal userPrincipal, TokenType type, long expirySeconds) {
        return JWT.create().withIssuer(issuer)
                .withClaim("userId", userPrincipal.getUserId())
                .withClaim("roleName", userPrincipal.getRole().name())
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
