package appsecurity.auth.repository;

import appsecurity.auth.AuthToken;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface AuthTokenRepository extends CrudRepository<AuthToken, Long> {
    Optional<AuthToken> findByUserId(Long userId);
}
