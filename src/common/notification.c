#include "sentinel_notification.h"
#include "sentinel_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

void sentinel_send_sms(const char *to_number, const char *message) {
    char *sid = getenv("TWILIO_ACCOUNT_SID");
    char *token = getenv("TWILIO_AUTH_TOKEN");
    char *from = getenv("TWILIO_FROM_NUMBER");

    // Local logging fallback
    if (!sid || !token || !from) {
        sentinel_log(LOG_LEVEL_INFO, "[ALERT] SMS sent to %s: \"%s\" (Twilio credentials missing - simulation mode)", to_number, message);
        return;
    }

    sentinel_log(LOG_LEVEL_INFO, "SMS NOTIFICATION: Sending API request to Twilio for To: %s", to_number);

    pid_t pid = fork();
    if (pid == 0) { // Child process
        // Redirect stdout/stderr to /dev/null to avoid printing raw curl outputs
        FILE *dev_null = fopen("/dev/null", "w");
        if (dev_null) {
            dup2(fileno(dev_null), STDOUT_FILENO);
            dup2(fileno(dev_null), STDERR_FILENO);
            fclose(dev_null);
        }

        char auth[256];
        snprintf(auth, sizeof(auth), "%s:%s", sid, token);

        char url[512];
        snprintf(url, sizeof(url), "https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", sid);

        char *args[] = {
            "curl",
            "-s",
            "-X", "POST",
            url,
            "--data-urlencode", "To",
            (char *)to_number,
            "--data-urlencode", "From",
            from,
            "--data-urlencode", "Body",
            (char *)message,
            "-u",
            auth,
            NULL
        };

        execvp("curl", args);
        exit(1); // Exit if exec failed
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
}
