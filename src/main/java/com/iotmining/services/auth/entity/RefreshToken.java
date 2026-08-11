package com.iotmining.services.auth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Rotation with reuse detection: every token issued from one login shares a
 * {@code familyId}. Rotating a token marks the old row {@code revoked}
 * (never hard-deleted while still unexpired) and inserts a new row with the
 * same familyId. A refresh request presenting an already-revoked token means
 * someone replayed a token this service already rotated away from - a sign
 * the token was stolen - and AuthenticationController responds by revoking
 * every row in that familyId, not just the one presented.
 *
 * {@code user} is @ManyToOne (not @OneToOne) precisely because a revoked
 * row and its successor legitimately coexist for a user until the revoked
 * one expires and TokenCleanupService sweeps it.
 */
@Entity(name = "refreshtoken")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "user_id")
    private User user;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(name = "family_id", nullable = false)
    private UUID familyId;

    @Column(name = "revoked", nullable = false)
    @Builder.Default
    private boolean revoked = false;

    @Column(name = "revoked_at")
    private Instant revokedAt;
}
