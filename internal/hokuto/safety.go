package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

var forbiddenSystemDirs = map[string]struct{}{
	"/bin":   {},
	"/lib":   {},
	"/lib32": {},
	"/lib64": {},
	"/opt":   {},
	"/sbin":  {},
	"/usr":   {},
	"/var":   {},
	"/etc":   {},
	"/swap":  {},
	// Common subdirectories
	"/etc/profile.d":           {},
	"/usr/bin":                 {},
	"/usr/include":             {},
	"/usr/lib":                 {},
	"/usr/lib32":               {},
	"/usr/lib64":               {},
	"/usr/local":               {},
	"/usr/sbin":                {},
	"/usr/share":               {},
	"/usr/src":                 {},
	"/usr/share/man":           {},
	"/usr/share/man/man1":      {},
	"/usr/share/man/man2":      {},
	"/usr/share/man/man3":      {},
	"/usr/share/man/man4":      {},
	"/usr/share/man/man5":      {},
	"/usr/share/man/man6":      {},
	"/usr/share/man/man7":      {},
	"/usr/share/man/man8":      {},
	"/var/cache":               {},
	"/var/db":                  {},
	"/var/db/hokuto":           {},
	"/var/db/hokuto/installed": {},
	"/var/db/hokuto/sources":   {},
	"/var/empty":               {},
	"/var/lib":                 {},
	"/var/local":               {},
	"/var/lock":                {},
	"/var/log":                 {},
	"/var/mail":                {},
	"/var/opt":                 {},
	"/var/run":                 {},
	"/var/service":             {},
	"/var/spool":               {},
	"/var/tmp":                 {},
	"/var/tmpdir":              {},
	"/var/lib/misc":            {},
	"/var/spool/mail":          {},
	"/var/log/old":             {},
}

// list of essential directories that should NEVER be removed, nor should any of their contents.
// These use a prefix check (recursive protection).

var forbiddenSystemDirsRecursive = map[string]struct{}{
	"/boot":      {},
	"/dev":       {},
	"/home":      {},
	"/mnt":       {},
	"/proc":      {},
	"/root":      {},
	"/sys":       {},
	"/tmp":       {},
	"/run":       {},
	"/snapshots": {},
	"/repo":      {},
}
