// Offline fixture producer. Imports the unchanged pinned native model/loader.
// Never observes a host or runs a recipe.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/jerryfane/macserve/internal/profiles"
)

func main() {
	registry, err := profiles.Load("/dev/stdin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	list := registry.List()
	digests := make(map[string]string, len(list))
	for _, profile := range list {
		// Exact maintenance.go observation producer, independently executed.
		raw, err := json.Marshal(profile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		sum := sha256.Sum256(raw)
		digests[profile.ID] = hex.EncodeToString(sum[:])
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"profiles": list, "digests": digests,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
