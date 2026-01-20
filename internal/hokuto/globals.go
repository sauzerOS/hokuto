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
	defaultBinaryMirror  string  // hardcoded at build time via -X
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
	PkgsetFile       = "/etc/hokuto.pkgset"
	versionedPkgDirs = make(map[string]string) // pkgName@version -> tmpDir
)

// Packages that have multilib variants (32-bit library support)
// When HOKUTO_MULTILIB=1 or -multi flag is used, these packages
// will have their "-multi" variant installed instead of the regular version.
var MultilibPackages = []string{
	"acl",
	"alsa-lib",
	"attr",
	"brotli",
	"bzip2",
	"cairo",
	"curl",
	"dbus",
	"dxvk",
	"dxvk-nvapi",
	"expat",
	"fdk-aac",
	"ffmpeg",
	"flac",
	"fluidsynth",
	"fontconfig",
	"freetype",
	"gamemode",
	"gcc",
	"gdbm",
	"glib",
	"glibc",
	"glslang",
	"gmp",
	"gnutls",
	"gst-plugins-bad",
	"gst-plugins-base",
	"gst-plugins-good",
	"gst-plugins-ugly",
	"gstreamer",
	"harfbuzz",
	"icu",
	"kmod",
	"lame",
	"libICE",
	"libSM",
	"libX11",
	"libXScrnSaver",
	"libXau",
	"libXcomposite",
	"libXcursor",
	"libXdamage",
	"libXdmcp",
	"libXext",
	"libXfixes",
	"libXfont2",
	"libXft",
	"libXi",
	"libXinerama",
	"libXmu",
	"libXrandr",
	"libXrender",
	"libXres",
	"libXt",
	"libXtst",
	"libXv",
	"libXxf86vm",
	"libaom",
	"libcap",
	"libdrm",
	"libelf",
	"libffi",
	"libfontenc",
	"libglvnd",
	"libidn2",
	"libogg",
	"libpciaccess",
	"libpng",
	"libpsl",
	"libsndfile",
	"libtasn1",
	"libtirpc",
	"libtool",
	"libunistring",
	"libunwind",
	"libvdpau",
	"libvorbis",
	"libvpx",
	"libxcb",
	"libxcrypt",
	"libxcvt",
	"libxkbcommon",
	"libxkbfile",
	"ibxml2",
	"libxpm",
	"libxpresent",
	"libxshmfence",
	"mangohud",
	"mesa-gbm",
	"mingw",
	"mingw-binutils",
	"mingw-gcc",
	"mingw-gcc-static",
	"mingw-headers",
	"mingw-winpthreads",
	"ncurses",
	"nettle",
	"nspr",
	"nss",
	"nvidia",
	"openssl",
	"opus",
	"pam",
	"pcre2",
	"pipewire",
	"pixman",
	"pulseaudio",
	"readline",
	"rust",
	"sdl2-compat",
	"sdl3",
	"spirv-llvm-translator",
	"spirv-tools",
	"sqlite",
	"systemd",
	"util-linux",
	"vkd3d-proton",
	"vulkan-loader",
	"wayland",
	"x264",
	"x265",
	"xz",
	"zlib-ng",
	"zstd",
}

// color helpers
var (
	colInfo    = color.Info // style provided by gookit/color
	colWarn    = color.Warn
	colError   = color.Error
	colSuccess = color.HEX("#1976D2")
	colArrow   = color.HEX("#FFEB3B")
	colNote    = color.Tag("notice")
)
