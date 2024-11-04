package appsecurity.auth.jwt;

import appsecurity.auth.AuthUser;
import appsecurity.auth.TokenType;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static appsecurity.auth.TokenType.ACCESS;
import static appsecurity.auth.TokenType.REFRESH;
import static appsecurity.auth.jwt.JwtClaims.*;

/**
 * Reference : https://github.com/auth0/java-jwt/blob/master/EXAMPLES.md
 */
@Component
public class JwtProvider { // todo provider와 util 중 역할 고민해보고 리팩토링 후 이름 변경 고려
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

    public String createToken(AuthUser authUser, TokenType type) {
        return createToken(authUser, type, expirySecondsMap.get(type));
    }

    private String createToken(AuthUser authUser, TokenType type, long expirySeconds) { //todo authUser, Role 등 외부 의존성 JwtAuthenticationProvider로 빼내기
        List<String> roles = authUser.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return JWT.create().withIssuer(issuer)
                .withClaim(USER.getClaimName(), authUser.getUserId())
                .withClaim(ROLES.getClaimName(), roles)
                .withClaim(TYPE.getClaimName(), type.name())
                .withClaim(SALT.getClaimName(), randomSalt.nextInt())
                .withExpiresAt(Instant.now().plus(expirySeconds, ChronoUnit.SECONDS))
                .sign(algorithm);
    }

    public Claims validate(String token) throws JwtValidationException{
        try {
            Map<String, Claim> claims = jwtVerifier.verify(token).getClaims();
            Long userId = claims.get(USER.getClaimName()).asLong();
            TokenType type = TokenType.valueOf(claims.get(TYPE.getClaimName()).asString());
            List<String> roles = claims.get(ROLES.getClaimName()).asList(String.class);
            return new Claims(userId, type, roles);
        } catch (JWTVerificationException e) {
            throw new JwtValidationException();
        }
    }

    public Claims validate(String jwt, TokenType requiredType) throws JwtValidationException{
        Claims claims = validate(jwt);
        if (claims.type != requiredType) {
            throw new JwtValidationException("유효하지 않은 타입의 토큰입니다.");
        }
        return claims;
    }

    public record Claims(Long userId, TokenType type, List<String> roles) {
    }
}
