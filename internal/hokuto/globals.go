package hokuto

import (
	"embed"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/gookit/color"
)

// GLOBAL STATE
// We use a value of 1 for critical and 0 for non-critical/default.
var isCriticalAtomic atomic.Int32

// Global variables
var (
	rootDir              string
	CacheDir             string
	SourcesDir           string
	BinDir               string
	CacheStore           string
	Installed            string
	repoPaths            string
	tmpDir               string
	HokutoTmpDir         string
	WantStrip            string
	WantDebug            string
	Debug                bool
	Verbose              bool
	WantLTO              string
	newPackageDir        string
	setIdlePriority      bool
	buildPriority        string
	EnableMultilib       bool
	ConfigFile           = "/etc/hokuto.conf"
	gnuMirrorURL         string
	gnuOriginalURL       = "https://ftp.gnu.org/gnu"
	gnuMirrorMessageOnce sync.Once
	BinaryMirror         string
	version              = "dev" //default version; overridden at build time
	arch                 = runtime.GOARCH
	buildDate            = "unknown" // overridden at build time
	errPackageNotFound   = errors.New("package not found")
	// Global executors (declared, to be assigned in main)
	UserExec *Executor
	RootExec *Executor
	//go:embed assets/*.png
	embeddedImages embed.FS
	//go:embed assets/ca-bundle.crt
	embeddedAssets   embed.FS
	WorldFile        = "/var/db/hokuto/world"
	WorldMakeFile    = "/var/db/hokuto/world_make"
	LockFile         = "/etc/hokuto.lock"
	versionedPkgDirs = make(map[string]string) // pkgName@version -> tmpDir
)

// color helpers
var (
	colInfo    = color.Info // style provided by gookit/color
	colWarn    = color.Warn
	colError   = color.Error
	colSuccess = color.HEX("#1976D2")
	colArrow   = color.HEX("#FFEB3B")
	colNote    = color.Tag("notice")
)
