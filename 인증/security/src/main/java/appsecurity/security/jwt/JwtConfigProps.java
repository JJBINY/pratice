package appsecurity.security.jwt;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Setter
@Validated
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtConfigProps {

    @NotBlank
    String issuer;

    @NotBlank
    String secret;

    @Min(600) @Max(86400)
    long expirySeconds;

    @Min(129600) @Max(259200)
    long refreshExpirySeconds;
}
