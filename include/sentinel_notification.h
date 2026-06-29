#ifndef SENTINEL_NOTIFICATION_H
#define SENTINEL_NOTIFICATION_H

// Send an SMS notification to the target phone number using Twilio REST API
// if env vars are present, or fallback to detailed system logging.
void sentinel_send_sms(const char *to_number, const char *message);

#endif // SENTINEL_NOTIFICATION_H
