package appsecurity.auth.jwt;

public enum JwtClaims {
    USER("userId"),
    ROLES("roles"),
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
