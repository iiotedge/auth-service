package com.iotmining.services.auth.interfaces;

import com.iotmining.services.auth.validation.MinimumAgeValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Constraint(validatedBy = MinimumAgeValidator.class)
public @interface ValidateMinimumAge {

    int value() default 18;

    String message() default "Age must be at least {value} years old";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}