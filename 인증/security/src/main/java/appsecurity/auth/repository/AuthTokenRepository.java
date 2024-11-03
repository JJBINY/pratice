package appsecurity.auth.repository;

import appsecurity.auth.BlackedToken;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface AuthTokenRepository extends CrudRepository<BlackedToken, Long> {
    Optional<BlackedToken> findByUserId(Long userId);
}
