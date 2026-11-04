// Package assets carries the reviewed deployment assets inside the binary,
// so `macserve setup` stages exactly the assets of the release it runs.
package assets

import "embed"

// Deploy holds the assets deploy-install reads from its --assets
// directory, at the same relative paths.
//
//go:embed create-users.sh qualify.sh launchd/org.macserve.controller.plist.tmpl launchd/org.macserve.worker.plist.tmpl launchd/org.macserve.maintenance.plist.tmpl
var Deploy embed.FS

// DeployNames are the files in Deploy, in deploy-install's order.
var DeployNames = []string{
	"create-users.sh", "qualify.sh",
	"launchd/org.macserve.controller.plist.tmpl", "launchd/org.macserve.worker.plist.tmpl", "launchd/org.macserve.maintenance.plist.tmpl",
}
