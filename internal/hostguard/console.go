package hostguard

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ConsoleUID returns the owner of /dev/console: the user whose session is in
// the foreground, or root while loginwindow shows the login window.
func ConsoleUID() (uint32, error) {
	info, err := os.Stat("/dev/console")
	if err != nil {
		return 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("console owner unavailable")
	}
	return st.Uid, nil
}

// ConsoleAdmissible accepts only the qualified console states: the owner in
// the foreground, or the login window (root) after the owner chose Switch
// User. Jobs run in the job account's background GUI domain; a foreground job
// session (or any other account on the console) is not qualified, so it
// refuses rather than running there.
func ConsoleAdmissible(console, ownerUID uint32) error {
	if console == 0 || console == ownerUID {
		return nil
	}
	return fmt.Errorf("console is owned by uid %d: only the owner (uid %d) or the login window may hold /dev/console; a foreground job-account session is not qualified", console, ownerUID)
}

// CheckConsole reads /dev/console and applies ConsoleAdmissible.
func CheckConsole(ownerUID uint32) error {
	console, err := ConsoleUID()
	if err != nil {
		return fmt.Errorf("console owner unavailable: %w", err)
	}
	return ConsoleAdmissible(console, ownerUID)
}
