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
import static appsecurity.auth.jwt.JwtClaimName.*;

/**
 * Reference : https://github.com/auth0/java-jwt/blob/master/EXAMPLES.md
 */
@Component
public class JwtProvider { // todo JwtGenerator JwtValidator 추가
    private final String issuer;
    private final String secret;
    private final Map<JwtType, Long> expirySecondsMap;
    private final Algorithm algorithm;
    private final JWTVerifier jwtVerifier;
    private final Random randomSalt;
    private final UniqueIdGenerator uniqueIdGenerator;

    public JwtProvider(JwtConfigProps jwtConfigProps, UniqueIdGenerator uniqueIdGenerator) {
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
        this.uniqueIdGenerator = uniqueIdGenerator;
    }

    public Jwt generate(Long userId, List<String> roles, JwtType type) {
        return Jwt.builder()
                .value(generate(userId, roles, type, expirySecondsMap.get(type)))
                .expirySeconds(expirySecondsMap.get(type))
                .build();
    }

    private String generate(Long userId, List<String> roles, JwtType type, long expirySeconds) {
        return JWT.create().withIssuer(issuer)
                .withClaim(TOKEN_ID.claim(), uniqueIdGenerator.generate())
                .withClaim(USER_ID.claim(), userId)
                .withClaim(ROLES.claim(), roles)
                .withClaim(TYPE.claim(), type.name())
                .withClaim(SALT.claim(), randomSalt.nextInt())
                .withExpiresAt(Instant.now().plus(expirySeconds, ChronoUnit.SECONDS))
                .sign(algorithm);
    }

    public JwtClaims validate(String jwt) throws JwtValidationException {
        return parseClaims(decode(jwt));
    }

    private DecodedJWT decode(String jwt) throws JwtValidationException {
        try {
            return jwtVerifier.verify(jwt);
        } catch (JWTVerificationException e) {
            throw new JwtValidationException();
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
