package app.security;

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
    String header;
    @NotBlank
    String issuer;
    @NotBlank
    String secret;
    @Min(600) @Max(259200)
    long expirySeconds;

    public String getHeader() {
        return header;
    }
}
