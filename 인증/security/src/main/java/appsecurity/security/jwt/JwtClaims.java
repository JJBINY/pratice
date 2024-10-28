package appsecurity.security.jwt;

public enum JwtClaims {
    USER("userId"),
    ROLE("roleName"),
    TYPE("type"),
    SALT("salt");

    private String claimName;

    JwtClaims(String claimName) {
        this.claimName = claimName;
    }

    public String getClaimName() {
        return claimName;
    }
}
