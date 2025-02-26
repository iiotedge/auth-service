package com.iotmining.services.login_service.exceptions;


public class UserMessageException extends Exception {
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

    // Getter for user message
    public String getUserMessage() {
        return userMessage;
    }
}
