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
     * UPDATED: Now accepts ipAddress for security binding.
     */
    @Transactional
    public RefreshToken createRefreshToken(UUID userId, String ipAddress) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        // 1. DELETE EXISTING TOKEN
        refreshTokenRepository.deleteByUser(user);
        refreshTokenRepository.flush(); // Prevent Duplicate Key error

        // 2. CREATE NEW TOKEN
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());

        // 3. SET IP ADDRESS (Make sure your Entity has this field!)
        refreshToken.setIpAddress(ipAddress);

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
     * Rotates a token and PRESERVES the IP address of the original session.
     */
    @Transactional
    public RefreshToken rotateRefreshToken(RefreshToken oldToken) {
        // Pass the IP from the OLD token to the NEW one so the session stays bound to that IP
        return createRefreshToken(oldToken.getUser().getUserId(), oldToken.getIpAddress());
    }

    /**
     * NEW: Explicit delete by token string
     */
    @Transactional
    public void deleteByToken(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(refreshTokenRepository::delete);
    }

}

