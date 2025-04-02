package com.iotmining.services.auth.exceptions;


import lombok.Getter;

@Getter
public class UserMessageException extends RuntimeException {
    // Getter for user message
    private final String userMessage;

    // Constructor with only the user message
    public UserMessageException(String userMessage) {
        super(userMessage); // Pass the message to the superclass constructor
        this.userMessage = userMessage;
    }

    // Constructor with both user message and cause
    public UserMessageException(String userMessage, Throwable cause) {
        super(userMessage, cause); // Pass both message and cause to the superclass constructor
        this.userMessage = userMessage;
    }

}
