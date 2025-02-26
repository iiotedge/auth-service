package com.iotmining.services.login_service.interfaces;

import com.iotmining.services.login_service.validation.GenderValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Constraint(validatedBy = GenderValidator.class)
public @interface ValidateGender {
    public String message() default "Gender should be either male or female";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

}
