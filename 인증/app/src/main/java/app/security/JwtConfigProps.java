package app.security;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Setter
@Getter(value = AccessLevel.PACKAGE)
@Validated
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtConfigProps {

    @NotBlank
    private String header;
    @NotBlank
    private String issuer;
    @NotBlank
    private String secret;
    @Min(600) @Max(259200)
    private long expirySeconds;
}
