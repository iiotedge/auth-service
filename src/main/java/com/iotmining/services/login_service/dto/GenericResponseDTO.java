package com.iotmining.services.login_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GenericResponseDTO<T> {
    private String message;
    private Integer statusCode;
    private T data;
}
