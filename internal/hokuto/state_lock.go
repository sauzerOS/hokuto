package hokuto

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Two hokuto processes changing the installed packages at once (an update in
// one terminal, an install in another) could lose each other's world edits
// and place or remove files of the same package concurrently. pacman and
// xbps refuse a second transaction; hokuto serializes the changes instead:
// installing a package, removing one, and editing the world files hold an
// exclusive flock on the installed database directory. Builds run in
// parallel as before and only wait while they install.
//
// The lock is held per process: nested and concurrent changes inside one
// hokuto (an install pulling post-install dependencies, the parallel
// manager) share it, so it never deadlocks against itself.
var installedStateLock struct {
	mu    sync.Mutex
	depth int
	file  *os.File
}

// stateLockPollInterval is how often a waiting process retries the lock.
var stateLockPollInterval = 250 * time.Millisecond

// lockInstalledState takes the installed-state lock, waiting for another
// hokuto process that holds it, and returns its release. When the database
// directory cannot be opened (a fresh root before its first install) it
// returns without locking.
func lockInstalledState() func() {
	s := &installedStateLock
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.depth == 0 {
		s.file = openInstalledStateLockFile()
		if s.file != nil {
			if err := waitForStateFlock(s.file); err != nil {
				debugf("installed-state lock unavailable: %v\n", err)
				s.file.Close()
				s.file = nil
			}
		}
	}
	s.depth++

	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.depth--
			if s.depth == 0 && s.file != nil {
				_ = unix.Flock(int(s.file.Fd()), unix.LOCK_UN)
				s.file.Close()
				s.file = nil
			}
		})
	}
}

// openInstalledStateLockFile opens the installed database directory: a
// directory can be flocked through a read-only descriptor, so a normal user
// installing through sudo or run0 locks it too, without a lock file to
// create in a root-owned place.
func openInstalledStateLockFile() *os.File {
	f, err := os.Open(Installed)
	if err != nil {
		debugf("installed-state lock: cannot open %s: %v\n", Installed, err)
		return nil
	}
	return f
}

func waitForStateFlock(f *os.File) error {
	fd := int(f.Fd())
	err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EWOULDBLOCK) {
		return err
	}
	fmt.Fprintln(os.Stderr)
	fcPrintf(os.Stderr, colArrow, "-> ")
	fcPrintf(os.Stderr, colWarn, "Another hokuto process is changing the installed packages; waiting for it to finish\n")
	for {
		time.Sleep(stateLockPollInterval)
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			debugf("installed-state lock acquired after waiting\n")
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
	}
}
