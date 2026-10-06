package hokuto

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func withStateLockTestDir(t *testing.T) {
	t.Helper()
	oldInstalled, oldPoll := Installed, stateLockPollInterval
	Installed = t.TempDir()
	stateLockPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { Installed, stateLockPollInterval = oldInstalled, oldPoll })
}

func TestInstalledStateLockWaitsForOtherHolder(t *testing.T) {
	withStateLockTestDir(t)

	// Another process holds the lock: a separate open file description
	// conflicts with ours as another process's would.
	other, err := os.Open(Installed)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	acquired := make(chan func())
	go func() { acquired <- lockInstalledState() }()
	select {
	case release := <-acquired:
		release()
		t.Fatal("the lock was taken while another holder had it")
	case <-time.After(100 * time.Millisecond):
	}

	if err := unix.Flock(int(other.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case release := <-acquired:
		release()
	case <-time.After(2 * time.Second):
		t.Fatal("the lock was not taken after the other holder released it")
	}
}

func TestInstalledStateLockIsReentrantWithinProcess(t *testing.T) {
	withStateLockTestDir(t)

	outer := lockInstalledState()
	done := make(chan struct{})
	go func() {
		// A nested install (post-install dependencies) or a parallel
		// worker of the same process must not wait for itself.
		inner := lockInstalledState()
		inner()
		inner() // releasing twice is harmless
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a nested lock in the same process deadlocked")
	}

	// Still held by outer: another holder cannot take it.
	other, err := os.Open(Installed)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		t.Fatal("the lock was released while the outer holder still had it")
	}
	outer()
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("the lock was not released by the last holder: %v", err)
	}
}

func TestInstalledStateLockWithoutDatabaseDirectory(t *testing.T) {
	withStateLockTestDir(t)
	Installed = Installed + "/missing"
	lockInstalledState()()
}
