package appsecurity.auth.jwt;

import appsecurity.auth.exception.UnauthenticatedException;
import appsecurity.auth.UserPrincipal;
import appsecurity.auth.TokenType;
import appsecurity.auth.Role;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Random;

import static appsecurity.auth.TokenType.ACCESS;
import static appsecurity.auth.TokenType.REFRESH;
import static appsecurity.auth.jwt.JwtClaims.*;

/**
 * Reference : https://github.com/auth0/java-jwt/blob/master/EXAMPLES.md
 */
@Component
public class JwtProvider {
    private final String issuer;
    private final String secret;
    private final Map<TokenType, Long> expirySecondsMap;
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

    public String generateToken(UserPrincipal userPrincipal, TokenType type) {
        return generateToken(userPrincipal, type, expirySecondsMap.get(type));
    }

    private String generateToken(UserPrincipal userPrincipal, TokenType type, long expirySeconds) {
        return JWT.create().withIssuer(issuer)
                .withClaim(USER.getClaimName(), userPrincipal.getUserId())
                .withClaim(ROLE.getClaimName(), userPrincipal.getRole().name())
                .withClaim(TYPE.getClaimName(), type.name())
                .withClaim(SALT.getClaimName(), randomSalt.nextInt())
                .withExpiresAt(Instant.now().plus(expirySeconds, ChronoUnit.SECONDS))
                .sign(algorithm);
    }

    public Claims validate(String token) {
        try {
            DecodedJWT decodedJwt = jwtVerifier.verify(token);
            Long userId = decodedJwt.getClaim(USER.getClaimName()).asLong();
            Role role = Role.valueOf(decodedJwt.getClaim(ROLE.getClaimName()).asString());
            TokenType type = TokenType.valueOf(decodedJwt.getClaim(TYPE.getClaimName()).asString());
            return new Claims(userId, role, type);
        } catch (JWTVerificationException e) {
            throw new UnauthenticatedException("유효하지 않은 토큰입니다.");
        }
    }

    public Claims validate(String jwt, TokenType requiredType) {
        Claims claims = validate(jwt);
        if (claims.type != requiredType) {
            throw new UnauthenticatedException("유효하지 않은 타입의 토큰입니다.");
        }
        return claims;
    }

    public record Claims(Long userId, Role role, TokenType type) {
    }
}
