package appsecurity.auth.jwt;

public enum JwtClaimName {
    TOKEN_ID("tokenId"),
    USER_ID("userId"),
    ROLES("roles"),
    TYPE("type"),
    SALT("salt");

    private String claim;

    JwtClaimName(String claim) {
        this.claim = claim;
    }

    public String claim() {
        return claim;
    }
}
