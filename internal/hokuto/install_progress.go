package hokuto

import (
	"fmt"
	"os"

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
	p.deactivate = activateProgressLineFinisher(p.endLine)
	return p
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
