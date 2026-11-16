#ifndef SENTRY_NOTIFY_H
#define SENTRY_NOTIFY_H

/* Start the seccomp user-notification supervisor thread.
 * notify_fd   : listener fd received from the sandboxed child (we own it).
 * events_path : JSON-lines file for observed events (NULL = do not log).
 * Returns 0 on success, -1 on failure. */
int  notify_start(int notify_fd, const char *events_path);

/* Stop the supervisor, close the listener fd and the events file. */
void notify_stop(void);

#endif