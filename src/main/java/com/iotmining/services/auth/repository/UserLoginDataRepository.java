package com.iotmining.services.auth.repository;

import com.iotmining.services.auth.entity.UserLoginData;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface UserLoginDataRepository extends JpaRepository<UserLoginData, UUID> {

    @Query("SELECT u.id FROM UserLoginData u WHERE u.tokenExpirationTime < :cutoff")
    List<UUID> findIdsExpiredBefore(@Param("cutoff") LocalDateTime cutoff, Pageable pageable);

    /** One bounded batch of a TokenCleanupService sweep - see its own doc comment for why this is batched. */
    default int deleteBatchByTokenExpirationTimeBefore(LocalDateTime cutoff, Pageable pageable) {
        List<UUID> ids = findIdsExpiredBefore(cutoff, pageable);
        if (!ids.isEmpty()) {
            deleteAllByIdInBatch(ids);
        }
        return ids.size();
    }
}
