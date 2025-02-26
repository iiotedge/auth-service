package com.iotmining.services.login_service.validation;


import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Arrays;
import java.util.List;

import com.iotmining.services.login_service.interfaces.ValidateGender;

public class GenderValidator implements ConstraintValidator<ValidateGender,String> {
    private final List<String> validGenders = Arrays.asList("male", "female");
    @Override
    public boolean isValid(String gender, ConstraintValidatorContext constraintValidatorContext) {
        return validGenders.contains(gender.toLowerCase());
    }
}