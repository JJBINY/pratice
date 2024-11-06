package appsecurity.auth.jwt;

public enum JwtClaims {
    USER_ID("userId"),
    ROLES("roles"),
    TYPE("type"),
    SALT("salt");

    private String claim;

    JwtClaims(String claim) {
        this.claim = claim;
    }

    public String claim() {
        return claim;
    }
}
