package appsecurity.auth.blacklist;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Component
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class TokenBlackList {
    private final BlackedTokenRepository blackedTokenRepository; // todo redis 전환

    @Transactional
    public void add(Long tokenId, Instant expiresAt) {
        blackedTokenRepository.save(new BlackedToken(tokenId, expiresAt));
    }

    public boolean isBlacked(Long tokenId) {
        return blackedTokenRepository.findById(tokenId).isPresent();
    }
}
