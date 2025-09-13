package com.iotmining.services.auth.dto;

import com.iotmining.common.data.notifications.NotificationStatus;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NotificationResponse {

    /** Notification channel like SMS, EMAIL, WEB, TELEGRAM, etc. */
    private String channel;

    /** Flag indicating if delivery was successful */
    private boolean delivered;

    /** Time when the notification was processed */
    @Builder.Default
    private Instant timestamp = Instant.now();

    /** Message or description of the delivery result */
    private String message;

    /** Enum indicating the status (SENT, FAILED, DELIVERED, etc.) */
    private NotificationStatus status;

    /** Unique correlation ID for tracking the notification */
    private UUID correlationId;
}
