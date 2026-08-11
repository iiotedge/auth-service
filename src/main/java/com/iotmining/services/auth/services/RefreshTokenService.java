package com.iotmining.services.auth.services;

import com.iotmining.services.auth.entity.RefreshToken;
import com.iotmining.services.auth.entity.User;
import com.iotmining.services.auth.repository.RefreshTokenRepository;
import com.iotmining.services.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${app.jwt.refreshExpirationMs}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    /**
     * Starts a brand new token family for a fresh login - any previous
     * session for this user is hard-deleted first (this service supports
     * one active session per user; an explicit new login intentionally
     * ends the old one, which is a different situation from rotation
     * reusing a family - see rotateRefreshToken).
     */
    @Transactional
    public RefreshToken createRefreshToken(UUID userId, String ipAddress) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        refreshTokenRepository.deleteByUser(user);
        refreshTokenRepository.flush(); // Prevent Duplicate Key error

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setIpAddress(ipAddress);
        refreshToken.setFamilyId(UUID.randomUUID());
        refreshToken.setRevoked(false);

        return refreshTokenRepository.save(refreshToken);
    }

    // Overload for backward compatibility (defaults to null IP)
    @Transactional
    public RefreshToken createRefreshToken(UUID userId) {
        return createRefreshToken(userId, null);
    }

    /**
     * Helper method to create token by username
     */
    @Transactional
    public RefreshToken createRefreshTokenByUsername(String username, String ipAddress) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found with username: " + username));
        return createRefreshToken(user.getUserId(), ipAddress);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    /**
     * Rotates a token within its existing family: marks the presented token
     * revoked (kept, not deleted, until it naturally expires - that's what
     * lets a later replay of this exact token be recognized as reuse) and
     * issues a new token carrying the same familyId and IP binding.
     * Deliberately does NOT go through createRefreshToken, since that
     * deletes all of the user's existing rows first - it would delete the
     * very row this method just marked revoked, destroying the reuse signal.
     */
    @Transactional
    public RefreshToken rotateRefreshToken(RefreshToken oldToken) {
        oldToken.setRevoked(true);
        oldToken.setRevokedAt(Instant.now());
        refreshTokenRepository.save(oldToken);

        RefreshToken newToken = new RefreshToken();
        newToken.setUser(oldToken.getUser());
        newToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        newToken.setToken(UUID.randomUUID().toString());
        newToken.setIpAddress(oldToken.getIpAddress());
        newToken.setFamilyId(oldToken.getFamilyId());
        newToken.setRevoked(false);

        return refreshTokenRepository.save(newToken);
    }

    /**
     * Reuse-detection response - revokes every token in the family, not
     * just the one that was replayed, so a legitimate token an attacker
     * hasn't used yet (or vice versa) is invalidated too. Forces a full
     * re-login.
     */
    @Transactional
    public void revokeFamily(UUID familyId) {
        refreshTokenRepository.revokeFamily(familyId, Instant.now());
    }

    /**
     * NEW: Explicit delete by token string
     */
    @Transactional
    public void deleteByToken(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(refreshTokenRepository::delete);
    }

    /** Ends every active session for a user - used when a password reset or account compromise means every existing session must die. */
    @Transactional
    public void revokeAllForUser(User user) {
        refreshTokenRepository.deleteByUser(user);
    }
}
