package com.iotmining.services.auth.validation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("GenderValidator")
class GenderValidatorTest {

    private final GenderValidator validator = new GenderValidator();

    @ParameterizedTest(name = "accepts \"{0}\"")
    @ValueSource(strings = {"male", "female", "MALE", "FEMALE", "Male", "Female"})
    @DisplayName("accepts male/female in any casing")
    void acceptsSupportedGenders(String gender) {
        assertThat(validator.isValid(gender, null)).isTrue();
    }

    @ParameterizedTest(name = "rejects \"{0}\"")
    @ValueSource(strings = {"", " ", "unknown", "m", "f", "other", "OTHER"})
    @DisplayName("rejects unsupported values (note: OTHER is not accepted by the current implementation)")
    void rejectsUnsupportedGenders(String gender) {
        assertThat(validator.isValid(gender, null)).isFalse();
    }
}
