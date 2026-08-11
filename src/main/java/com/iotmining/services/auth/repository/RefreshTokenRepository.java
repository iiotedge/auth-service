package com.iotmining.services.auth.repository;

import com.iotmining.services.auth.entity.RefreshToken;
import com.iotmining.services.auth.entity.User;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    @Modifying
    void deleteByUser(User user);

    // RefreshToken's @Entity(name = "refreshtoken") sets an explicit JPQL
    // entity name, distinct from the Java class name - must match here too.
    @Query("SELECT r.id FROM refreshtoken r WHERE r.expiryDate < :cutoff")
    List<Long> findIdsExpiredBefore(@Param("cutoff") Instant cutoff, Pageable pageable);

    /** One bounded batch of a TokenCleanupService sweep - see its own doc comment for why this is batched. */
    default int deleteBatchByExpiryDateBefore(Instant cutoff, Pageable pageable) {
        List<Long> ids = findIdsExpiredBefore(cutoff, pageable);
        if (!ids.isEmpty()) {
            deleteAllByIdInBatch(ids);
        }
        return ids.size();
    }
}
