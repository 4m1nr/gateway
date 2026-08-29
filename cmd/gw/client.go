package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/am1nr/gateway/internal/cli"
	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/config/edit"
)

func cmdClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	var f commonFlags
	f.bind(fs)
	asJSON := fs.Bool("json", false, "emit the client list as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := f.resolve(); err != nil {
		return err
	}

	rest := fs.Args()
	if len(rest) == 0 {
		return fmt.Errorf("usage: gw client <list|add|rm> ...")
	}

	switch rest[0] {
	case "list":
		return clientList(f, *asJSON)
	case "add":
		if len(rest) < 3 {
			allowed, _ := knownPolicies(f)
			return fmt.Errorf("usage: gw client add <ip> <name> [%s]",
				strings.Join(allowed, " | "))
		}
		policy := "proxy"
		if len(rest) > 3 {
			policy = rest[3]
		}
		return clientAdd(f, rest[1], rest[2], policy)
	case "rm":
		if len(rest) != 2 {
			return fmt.Errorf("usage: gw client rm <ip>")
		}
		if err := edit.RemoveClient(f.paths.Config, rest[1]); err != nil {
			return err
		}
		fmt.Printf("removed %s; run `sudo gw apply` to make it live\n", rest[1])
		return nil
	}
	return fmt.Errorf("unknown subcommand: %s", rest[0])
}

// knownPolicies is the built-ins plus whatever profiles this config defines.
//
// The load error is returned rather than swallowed. Falling back to the
// built-ins silently is worse than useless: a valid profile name is then
// reported as "not defined", which sends you to look at the policy when the
// actual problem is somewhere else in the config entirely.
func knownPolicies(f commonFlags) ([]string, error) {
	cfg, err := config.Load(f.paths.Config)
	if err != nil {
		return config.BuiltinPolicies, err
	}
	return cfg.Policies, nil
}

func clientList(f commonFlags, asJSON bool) error {
	clients, err := edit.Clients(f.paths.Config)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if clients == nil {
			clients = []edit.Client{}
		}
		return enc.Encode(clients)
	}

	if cfg, err := config.Load(f.paths.Config); err == nil {
		if names := cfg.ProfileNames(); len(names) > 0 {
			fmt.Printf("# profiles available: %s\n\n", strings.Join(names, ", "))
		}
	} else {
		cli.Warn("the config does not currently load, so profiles are not listed: %v", err)
	}
	if len(clients) == 0 {
		fmt.Println("no overrides configured — every device using this box as its " +
			"gateway gets [policy].default")
		return nil
	}
	ipw, polw := 0, 0
	for _, c := range clients {
		ipw = max(ipw, len(c.IP))
		polw = max(polw, len(c.Policy))
	}
	for _, c := range clients {
		fmt.Printf("%-*s  %-*s  %s\n", ipw, c.IP, polw, c.Policy, c.Name)
	}
	return nil
}

func clientAdd(f commonFlags, ip, name, policy string) error {
	allowed, loadErr := knownPolicies(f)
	if !contains(allowed, policy) {
		if loadErr != nil {
			// The profile list is unknown because the config does not load, so
			// whether this policy exists is unknowable. Report the real problem.
			return fmt.Errorf("cannot tell whether %q is a valid policy, because "+
				"the config does not load:\n  %w", policy, loadErr)
		}
		return fmt.Errorf("policy %q is not defined. Known policies: %s\n"+
			"Profiles are declared with [[profile]] in gateway.toml",
			policy, strings.Join(allowed, ", "))
	}
	replaced, err := edit.AddClient(f.paths.Config, edit.Client{IP: ip, Name: name, Policy: policy})
	if err != nil {
		return err
	}
	if replaced != "" {
		fmt.Printf("replacing existing entry for %s (%s -> %s)\n", ip, replaced, policy)
	}
	fmt.Printf("%s (%s) -> %s\n", ip, name, policy)

	// Loading the whole config catches a policy that parses but does not exist,
	// and anything else the edit invalidated, before apply does.
	if _, err := config.Load(f.paths.Config); err != nil {
		cli.Warn("the config no longer loads: %v", err)
	}
	fmt.Println("run `sudo gw apply` to make it live")
	return nil
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
