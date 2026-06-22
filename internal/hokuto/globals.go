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
	UpdateWebsiteIndex   bool
	WantLTO              string
	VerifySignature      bool
	HokutoGeneric        bool
	GlobalAssumeYes      bool
	activeKeyID          string
	newPackageDir        string
	setIdlePriority      bool
	buildPriority        string
	EnableMultilib       bool
	ConfigFile           = "/etc/hokuto/hokuto.conf"
	gnuMirrorURL         string
	gnuOriginalURL       = "https://ftp.gnu.org/gnu"
	gnuMirrorMessageOnce sync.Once
	BinaryMirror         string
	PublicBinaryMirrors  []string
	defaultBinaryMirror  string  // hardcoded at build time via -X
	version              = "dev" //default version; overridden at build time
	arch                 = runtime.GOARCH
	buildDate            = "unknown" // overridden at build time
	errPackageNotFound   = errors.New("package not found")
	// Global executors (declared, to be assigned in main)
	UserExec               *Executor
	RootExec               *Executor
	activePrivilegeBackend privilegeBackend
	//go:embed assets/*.png
	embeddedImages embed.FS
	//go:embed assets/ca-bundle.crt assets/git-hook-prepare-commit-msg
	embeddedAssets   embed.FS
	WorldFile        = "/var/db/hokuto/world"
	WorldMakeFile    = "/var/db/hokuto/world_make"
	LockFile         = "/etc/hokuto/hokuto.lock"
	PkgsetFile       = "/etc/hokuto/hokuto.pkgset"
	versionedPkgDirs = make(map[string]string) // pkgName@version -> tmpDir
	PkgDBPath        = "/var/db/hokuto/pkg-db.json.zst"
	BumpLogFile      = "/var/log/hokuto-bump.log"
	//go:embed assets/MIRROR
	embeddedMirrorList string

	// Cache for remote index to avoid multiple fetches
	GlobalRemoteIndex       []RepoEntry
	GlobalRemoteIndexLoaded bool
	GlobalRemoteIndexMu     sync.Mutex
)

// Packages that have multilib variants (32-bit library support)
// When HOKUTO_MULTILIB=1 or -multi flag is used, these packages
// will have their "-multi" variant installed instead of the regular version.
var MultilibPackages = []string{
	"05-libstdc++",
	"07-ncurses",
	"20-gcc-2",
	"24-bzip2",
	"alsa-lib",
	"cairo",
	"dxvk",
	"dxvk-nvapi",
	"fdk-aac",
	"ffmpeg",
	"flac",
	"fluidsynth",
	"fontconfig",
	"freetype",
	"gamemode",
	"gcc",
	"glibc",
	"glslang",
	"gnutls",
	"gst-plugins-bad",
	"gst-plugins-base",
	"gst-plugins-good",
	"gst-plugins-ugly",
	"gstreamer",
	"harfbuzz",
	"libICE",
	"libSM",
	"libx11",
	"libxscrnsaver",
	"libxau",
	"libxau",
	"libxcomposite",
	"libxcursor",
	"libxdamage",
	"libxdmcp",
	"libxext",
	"libxfixes",
	"libxfont2",
	"libxft",
	"libxi",
	"libxinerama",
	"libxmu",
	"libxrandr",
	"libxrender",
	"libxres",
	"libxt",
	"libxtst",
	"libxv",
	"libxxf86vm",
	"libaom",
	"libdrm",
	"libfontenc",
	"libglvnd",
	"libogg",
	"libpciaccess",
	"libpng",
	"libsndfile",
	"libtas",
	"libunwind",
	"libvdpau",
	"libvorbis",
	"libvpx",
	"libxcb",
	"libxcrypt",
	"libxcvt",
	"libxkbcommon",
	"libxkbfile",
	"libxpm",
	"libxpresent",
	"libxshmfence",
	"llvm-32",
	"mangohud",
	"mesa-32",
	"mesa-gbm",
	"mingw",
	"mingw-binutils",
	"mingw-gcc",
	"mingw-gcc-static",
	"mingw-headers",
	"mingw-winpthreads",
	"mpg123",
	"nettle",
	"nv-codec-headers",
	"nvidia",
	"opus",
	"pipewire",
	"pixman",
	"pulseaudio",
	"rust",
	"sdl2-compat",
	"sdl3",
	"spirv-llvm-translator",
	"spirv-tools",
	"twolame",
	"util-linux",
	"vkd3d-proton",
	"vulkan-loader",
	"wayland",
	"x264",
	"x265",
}

// color helpers
var (
	colInfo    = color.Info // style provided by gookit/color
	colWarn    = color.Warn
	colError   = color.Error
	colSuccess = color.HEX("#1976D2")
	colArrow   = color.HEX("#FFEB3B")
	colNote    = color.HEX("#0ba913") // Grey-ish color for notes/versions
)
