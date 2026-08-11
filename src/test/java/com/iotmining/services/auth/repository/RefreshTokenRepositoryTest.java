package com.iotmining.services.auth.repository;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageRequest;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("RefreshTokenRepository.deleteBatchByExpiryDateBefore")
class RefreshTokenRepositoryTest {

    // CALLS_REAL_METHODS lets the default method under test actually run,
    // while findIdsExpiredBefore/deleteAllByIdInBatch (both implemented by
    // Spring Data at runtime, not on the interface itself) stay stubbable.
    private final RefreshTokenRepository repository =
            mock(RefreshTokenRepository.class, org.mockito.Answers.CALLS_REAL_METHODS);

    @Test
    @DisplayName("deletes exactly the ids the query finds and returns how many")
    void deletesFoundIds() {
        Instant cutoff = Instant.now();
        PageRequest page = PageRequest.of(0, 500);
        when(repository.findIdsExpiredBefore(any(Instant.class), any())).thenReturn(List.of(1L, 2L, 3L));

        int deleted = repository.deleteBatchByExpiryDateBefore(cutoff, page);

        assertThat(deleted).isEqualTo(3);
        verify(repository).deleteAllByIdInBatch(List.of(1L, 2L, 3L));
    }

    @Test
    @DisplayName("does not call delete at all when nothing is expired")
    void skipsDeleteWhenNothingFound() {
        when(repository.findIdsExpiredBefore(any(Instant.class), any())).thenReturn(List.of());

        int deleted = repository.deleteBatchByExpiryDateBefore(Instant.now(), PageRequest.of(0, 500));

        assertThat(deleted).isZero();
        verify(repository, never()).deleteAllByIdInBatch(any());
    }
}
