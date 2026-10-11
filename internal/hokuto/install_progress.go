package hokuto

import (
	"fmt"
	"os"
	"sync"

	"github.com/schollz/progressbar/v3"
)

// installProgress is the "Installing Packages" bar of "hokuto install",
// shared by the updates: one line, the package being installed and the
// count, while each package installs quietly (the installer's fast mode).
// A nil *installProgress, for a run that prints each step instead, does
// nothing.
type installProgress struct {
	bar        *progressbar.ProgressBar
	verb       string
	lineActive bool
	deactivate func()
}

func newInstallProgress(total int) *installProgress {
	return newPackageProgress(total, "Installing")
}

// newRemoveProgress is the same bar for "hokuto uninstall --purge".
func newRemoveProgress(total int) *installProgress {
	return newPackageProgress(total, "Removing")
}

func newPackageProgress(total int, verb string) *installProgress {
	if total <= 0 {
		return nil
	}
	p := &installProgress{verb: verb}
	// progressbar.Default without its 65 ms throttle: with it, a label set
	// while packages go by quickly was not drawn, and a slow post-install
	// hook that followed sat under the name of an earlier package
	// (shared-mime-info's 3 s update-mime-database looked like x265
	// hanging). The bar is redrawn once per package.
	p.bar = progressbar.NewOptions64(int64(total),
		progressbar.OptionSetDescription(colSuccess.Sprint(verb+" Packages")),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetWidth(10),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionOnCompletion(func() { fmt.Fprint(os.Stderr, "\n") }),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
	)
	p.lineActive = true
	// Output from nested operations starts on a fresh line.
	finisherOff := activateProgressLineFinisher(p.endLine)
	activeInstallProgresses.Lock()
	activeInstallProgresses.stack = append(activeInstallProgresses.stack, p)
	activeInstallProgresses.Unlock()
	p.deactivate = func() {
		finisherOff()
		activeInstallProgresses.Lock()
		if n := len(activeInstallProgresses.stack); n > 0 && activeInstallProgresses.stack[n-1] == p {
			activeInstallProgresses.stack = activeInstallProgresses.stack[:n-1]
		}
		activeInstallProgresses.Unlock()
	}
	return p
}

// activeInstallProgresses are the bars being shown, innermost last, so a
// post-install hook can print above the current one.
var activeInstallProgresses struct {
	sync.Mutex
	stack []*installProgress
}

// currentInstallProgress is the bar being shown, or nil.
func currentInstallProgress() *installProgress {
	activeInstallProgresses.Lock()
	defer activeInstallProgresses.Unlock()
	if n := len(activeInstallProgresses.stack); n > 0 {
		return activeInstallProgresses.stack[n-1]
	}
	return nil
}

// suspend clears the bar's line, so output (a kernel's post-install hook:
// depmod, initramfs, boot entry) takes its place instead of following a
// half-drawn bar. The next start or advance draws the bar again, on the line
// below that output.
func (p *installProgress) suspend() {
	if p == nil {
		return
	}
	if p.lineActive {
		_ = p.bar.Clear()
	}
	p.lineActive = false
}

// endLine moves below the bar, so a message or prompt does not end up
// appended to it; the next update draws it again.
func (p *installProgress) endLine() {
	if p == nil || !p.lineActive {
		return
	}
	fmt.Fprintln(os.Stderr)
	p.lineActive = false
}

// start labels the bar with the package now installing.
func (p *installProgress) start(pkgName string) {
	if p == nil {
		return
	}
	p.bar.Describe(colSuccess.Sprint(p.verb+" ") + colNote.Sprint(pkgName))
	// Describe only stores the label; draw it now.
	_ = p.bar.RenderBlank()
	p.lineActive = true
}

// advance counts one package done.
func (p *installProgress) advance() {
	if p == nil {
		return
	}
	_ = p.bar.Add(1)
	p.lineActive = true
}

// finish ends the bar (full when everything succeeded) and its line.
func (p *installProgress) finish(succeeded bool) {
	if p == nil {
		return
	}
	if succeeded {
		_ = p.bar.Finish()
		p.lineActive = true
	}
	p.endLine()
	p.deactivate()
}

// clearProgressForPrompt makes room for a question asked while a progress bar
// is shown: the install bar's line is cleared for it, so the question does
// not follow the bar on its line, and the next package draws the bar again
// below the answer. Other bars end their line.
func clearProgressForPrompt() {
	if p := currentInstallProgress(); p != nil {
		p.suspend()
		return
	}
	prepareDependencyProgressLogOutput()
}
