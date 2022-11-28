/*
Package log provides global output control across the whole application. Logging comes in
four levels: Silent, Major, Minor and Debug which each level more detailed than the
previous. It's up to the application to decided which output belong with which
level. Levels are inclusive, so, e.g., if MinorLevel is set that implies MajorLevel
logging.

In general an application should have *all* output go via the logging interface once it
has completed successful parsing on the command line. One exception might be
start-up/shut-down messages, just in case logging is not working or has been redirected to
a null consumer.

The Print and Printf interface are similar to the fmt versions with a few subtle
differences due to the need to prefix lines. The main difference is that if the resulting
string contains multiple lines they are all printed with the prefix for the logging
level. The second different is that a trailing newline is not needed and excess ones are
trimmed.

Specialist logging functions external to this package should still use log.Out() to access
the current io.Writer for the purposes of capturing output for tests.
*/
package log
