package appsecurity.security.authentication;

import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface RefreshRepository extends CrudRepository<Refresh, Long> {
    Optional<Refresh> findByUserId(Long userId);
}
