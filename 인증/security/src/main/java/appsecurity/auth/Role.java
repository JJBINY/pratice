package appsecurity.auth;

public enum Role {
    USER("ROLE_USER"), ADMIN("ROLE_ADMIN");

    String role;
    Role(String role) {
        this.role = role;
    }

    public String role(){
        return role;
    }

    // Enum 값을 기반으로 Enum 인스턴스를 찾는 메서드
    public static Role roleOf(String roleString) { //todo rename
        for (Role role : Role.values()) {
            if (role.role().equals(roleString)) {
                return role;
            }
        }
        throw new IllegalArgumentException("No enum constant for roleString: " + roleString);
    }
}
