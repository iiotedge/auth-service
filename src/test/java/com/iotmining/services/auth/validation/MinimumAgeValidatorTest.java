package com.iotmining.services.auth.validation;

import com.iotmining.services.auth.interfaces.ValidateMinimumAge;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.lang.annotation.Annotation;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("MinimumAgeValidator (18+)")
class MinimumAgeValidatorTest {

    private MinimumAgeValidator validator;

    @BeforeEach
    void setUp() {
        validator = new MinimumAgeValidator();
        validator.initialize(minimumAge(18));
    }

    @Test
    @DisplayName("accepts someone well over the minimum age")
    void acceptsAdult() {
        assertThat(validator.isValid("1990-01-15", null)).isTrue();
    }

    @Test
    @DisplayName("accepts someone turning exactly 18 today")
    void acceptsExactly18Today() {
        String dob = LocalDate.now().minusYears(18).toString();
        assertThat(validator.isValid(dob, null)).isTrue();
    }

    @Test
    @DisplayName("rejects someone one day short of 18")
    void rejectsOneDayShort() {
        String dob = LocalDate.now().minusYears(18).plusDays(1).toString();
        assertThat(validator.isValid(dob, null)).isFalse();
    }

    @Test
    @DisplayName("rejects a 17-year-old")
    void rejectsMinor() {
        String dob = LocalDate.now().minusYears(17).toString();
        assertThat(validator.isValid(dob, null)).isFalse();
    }

    @Test
    @DisplayName("rejects a future date of birth")
    void rejectsFutureDate() {
        String dob = LocalDate.now().plusYears(1).toString();
        assertThat(validator.isValid(dob, null)).isFalse();
    }

    @ParameterizedTest(name = "rejects malformed input \"{0}\"")
    @ValueSource(strings = {"", "15-01-1990", "1990/01/15", "not-a-date", "1990-13-45"})
    @DisplayName("rejects malformed date strings instead of erroring")
    void rejectsMalformedDates(String dob) {
        assertThat(validator.isValid(dob, null)).isFalse();
    }

    /** Builds a literal @ValidateMinimumAge(value = minAge) instance for initialize(). */
    private static ValidateMinimumAge minimumAge(int minAge) {
        return new ValidateMinimumAge() {
            @Override public int value() { return minAge; }
            @Override public String message() { return ""; }
            @Override public Class<?>[] groups() { return new Class<?>[0]; }
            @Override @SuppressWarnings("unchecked") public Class<? extends jakarta.validation.Payload>[] payload() {
                return new Class[0];
            }
            @Override public Class<? extends Annotation> annotationType() { return ValidateMinimumAge.class; }
        };
    }
}
