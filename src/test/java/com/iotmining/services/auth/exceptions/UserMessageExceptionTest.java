package com.iotmining.services.auth.exceptions;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UserMessageExceptionTest {

    @Test
    void carriesTheUserMessage() {
        UserMessageException e = new UserMessageException("Account is disabled.");

        assertThat(e.getUserMessage()).isEqualTo("Account is disabled.");
        assertThat(e.getMessage()).isEqualTo("Account is disabled.");
        assertThat(e.getCause()).isNull();
    }

    @Test
    void carriesTheUserMessageAndCause() {
        Throwable cause = new IllegalStateException("root cause");

        UserMessageException e = new UserMessageException("Something went wrong.", cause);

        assertThat(e.getUserMessage()).isEqualTo("Something went wrong.");
        assertThat(e.getCause()).isSameAs(cause);
    }
}
