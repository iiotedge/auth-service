package com.iotmining.services.auth.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

import com.iotmining.services.auth.interfaces.ValidateMinimumAge;

public class MinimumAgeValidator implements ConstraintValidator<ValidateMinimumAge,String> {
    private int minAge;
    private DateTimeFormatter dateFormatter;


    @Override
    public void initialize(ValidateMinimumAge validateMinAge) {
        this.minAge = validateMinAge.value();
        this.dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    }
    @Override
    public boolean isValid(String dateOfBirth, ConstraintValidatorContext constraintValidatorContext) {
        try{
        LocalDate dob = LocalDate.parse(dateOfBirth, dateFormatter);
        return Period.between(dob, LocalDate.now()).getYears() >= minAge;
        } catch (DateTimeParseException e) {
            return false;
        }
    }
}