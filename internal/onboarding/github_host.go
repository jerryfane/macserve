package onboarding

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/profiles"
)

// Host describes the process and installation connect-github runs on.
// Root is deploy.Prefix and RootUID 0 outside tests.
type Host struct {
	Root    string
	RootUID uint32
	EUID    int
	SudoUID string
	// ConsoleUID is the user logged in at the Mac's screen.
	ConsoleUID func() (uint32, error)
}

// SystemConsoleUID reads the owner of /dev/console.
func SystemConsoleUID() (uint32, error) {
	info, err := os.Stat("/dev/console")
	if err != nil {
		return 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("cannot read the console owner")
	}
	return st.Uid, nil
}

// Prepared is an installation ready for connect-github.
type Prepared struct {
	OwnerUID   uint32
	Controller controller.Config
	Config     ConfigFile
	Key        KeyTarget
	Profiles   *profiles.Registry
}

// Prepare refuses, before anything is created on GitHub: a process that
// is not root through sudo from the console owner's login; a Mac without
// a deploy-install; an approved qualification (changing controller.json
// then breaks the activation anchor); an existing App key or github
// section.
func Prepare(h Host) (Prepared, error) {
	var p Prepared
	if h.EUID != int(h.RootUID) {
		return p, errors.New("run it with sudo: it installs the App key controller-owned and edits the root-owned controller.json")
	}
	uid, err := strconv.ParseUint(h.SudoUID, 10, 32)
	if h.SudoUID == "" || err != nil || uid == 0 || strconv.FormatUint(uid, 10) != h.SudoUID {
		return p, errors.New("run it with sudo from your own login, not from a root shell: SUDO_UID must name you")
	}
	p.OwnerUID = uint32(uid)
	console, err := h.ConsoleUID()
	if err != nil {
		return p, fmt.Errorf("cannot read the console user: %w", err)
	}
	if console != p.OwnerUID {
		return p, errors.New("run it from the login of the user at this Mac's screen; SUDO_UID is a different user")
	}
	config := filepath.Join(h.Root, "config")
	env, err := deploy.LoadEnvironment(filepath.Join(config, "deploy.env"))
	if err != nil {
		return p, fmt.Errorf("no deploy-install found (%v); install macserve with deploy-install first", err)
	}
	if env.OwnerUID != p.OwnerUID {
		return p, errors.New("SUDO_UID is not the OWNER_UID of deploy.env")
	}
	for _, name := range []string{"activation-anchor.json", "qualification.json"} {
		if _, err := os.Lstat(filepath.Join(config, name)); err == nil {
			return p, errors.New("qualification is already approved; adding the App now changes controller.json and needs requalification, which connect-github does not do")
		} else if !errors.Is(err, fs.ErrNotExist) {
			return p, err
		}
	}
	p.Config = ConfigFile{Path: filepath.Join(config, "controller.json"), RootUID: h.RootUID}
	if p.Controller, err = p.Config.Check(); err != nil {
		return p, err
	}
	if p.Controller.OwnerUID != p.OwnerUID {
		return p, errors.New("SUDO_UID is not the owner_uid of controller.json")
	}
	p.Key = KeyTarget{Root: h.Root, RootUID: h.RootUID, ControllerUID: env.ControllerUID, ControllerGID: env.ControllerGID}
	if exists, err := p.Key.KeyInstalled(); err != nil {
		return p, err
	} else if exists {
		return p, ErrKeyExists
	}
	if p.Profiles, err = profiles.Load(p.Controller.ProfilesFile); err != nil {
		return p, fmt.Errorf("profiles.json: %w", err)
	}
	return p, nil
}

// Repository picks the policy repository: name if given, else the single
// receipt pin. It must be pinned.
func (p Prepared) Repository(name string) (string, int64, error) {
	pins := p.Controller.Receipt.Repositories
	if name == "" {
		if len(pins) != 1 {
			return "", 0, errors.New("controller.json pins several repositories; choose one with --repository OWNER/NAME")
		}
		for repo, id := range pins {
			return repo, id, nil
		}
	}
	id := pins[name]
	if id <= 0 {
		return "", 0, fmt.Errorf("%s is not pinned in controller.json receipt.repositories (deploy.env REPOSITORIES)", name)
	}
	return name, id, nil
}
