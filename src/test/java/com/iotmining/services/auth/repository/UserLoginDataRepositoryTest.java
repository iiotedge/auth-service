package com.iotmining.services.auth.repository;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageRequest;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("UserLoginDataRepository.deleteBatchByTokenExpirationTimeBefore")
class UserLoginDataRepositoryTest {

    // CALLS_REAL_METHODS lets the default method under test actually run,
    // while findIdsExpiredBefore/deleteAllByIdInBatch (both implemented by
    // Spring Data at runtime, not on the interface itself) stay stubbable.
    private final UserLoginDataRepository repository =
            mock(UserLoginDataRepository.class, org.mockito.Answers.CALLS_REAL_METHODS);

    @Test
    @DisplayName("deletes exactly the ids the query finds and returns how many")
    void deletesFoundIds() {
        UUID id1 = UUID.randomUUID();
        UUID id2 = UUID.randomUUID();
        LocalDateTime cutoff = LocalDateTime.now();
        PageRequest page = PageRequest.of(0, 500);
        when(repository.findIdsExpiredBefore(any(LocalDateTime.class), any())).thenReturn(List.of(id1, id2));

        int deleted = repository.deleteBatchByTokenExpirationTimeBefore(cutoff, page);

        assertThat(deleted).isEqualTo(2);
        verify(repository).deleteAllByIdInBatch(List.of(id1, id2));
    }

    @Test
    @DisplayName("does not call delete at all when nothing is expired")
    void skipsDeleteWhenNothingFound() {
        when(repository.findIdsExpiredBefore(any(LocalDateTime.class), any())).thenReturn(List.of());

        int deleted = repository.deleteBatchByTokenExpirationTimeBefore(LocalDateTime.now(), PageRequest.of(0, 500));

        assertThat(deleted).isZero();
        verify(repository, never()).deleteAllByIdInBatch(any());
    }
}
