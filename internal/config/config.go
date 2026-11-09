// Package config loads the relay's YAML configuration.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"alatyr/internal/awgconf"
)

// Config is the relay configuration file.
type Config struct {
	// VPN is the upstream AmneziaWG config (path relative to this file).
	VPN string `yaml:"vpn"`
	// HTTPPort is the web UI port.
	HTTPPort int `yaml:"http_port"`
	// HTTPListen is the web UI bind address (default 0.0.0.0).
	HTTPListen string `yaml:"http_listen"`
	// PublicHost is written into user configs as Endpoint host. Empty means
	// "the host name used to open the web UI".
	PublicHost string `yaml:"public_host"`
	// DataFile stores users, keys and the admin password hash.
	DataFile string `yaml:"data_file"`
	// Subnet for relay users; the first address belongs to the relay.
	Subnet string `yaml:"subnet"`
	// DNS servers given to users (default: DNS from the upstream config).
	DNS []string `yaml:"dns"`
	// MTU for user configs (default: upstream MTU or 1280).
	MTU int `yaml:"mtu"`
	// Ports maps protocol (awg1, awg2, awg3) to UDP listen port; 0 disables.
	Ports map[string]int `yaml:"ports"`
	// ListsDir caches downloaded rule subscriptions.
	ListsDir string `yaml:"lists_dir"`
	// LogLevel: info or debug.
	LogLevel string `yaml:"log_level"`
	// LogFile, if set, receives logs in addition to stdout.
	LogFile string `yaml:"log_file"`

	dir string
}

// Load reads and validates the config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c.dir = filepath.Dir(abs)
	if c.VPN == "" {
		return nil, fmt.Errorf("%s: 'vpn' (path to the upstream AmneziaWG config) is required", path)
	}
	if c.HTTPPort == 0 {
		c.HTTPPort = 8080
	}
	if c.HTTPListen == "" {
		c.HTTPListen = "0.0.0.0"
	}
	if c.DataFile == "" {
		c.DataFile = "alatyr-data.json"
	}
	if c.ListsDir == "" {
		c.ListsDir = "lists-cache"
	}
	if c.Subnet == "" {
		c.Subnet = "10.66.66.0/24"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Ports == nil {
		c.Ports = map[string]int{awgconf.ProtoAWG1: 51821, awgconf.ProtoAWG2: 51822, awgconf.ProtoAWG3: 51823}
	}
	for proto, port := range c.Ports {
		if awgconf.ProtocolTitle(proto) == proto {
			return nil, fmt.Errorf("ports: unknown protocol %q (use awg1, awg2, awg3)", proto)
		}
		if port < 0 || port > 65535 {
			return nil, fmt.Errorf("ports: bad port %d for %s", port, proto)
		}
	}
	p, err := netip.ParsePrefix(c.Subnet)
	if err != nil || !p.Addr().Is4() || p.Bits() > 30 {
		return nil, fmt.Errorf("subnet: need an IPv4 prefix like 10.66.66.0/24")
	}
	return c, nil
}

// Path resolves a path relative to the config file directory.
func (c *Config) Path(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.dir, p)
}

// SubnetPrefix returns the parsed users' subnet.
func (c *Config) SubnetPrefix() netip.Prefix {
	return netip.MustParsePrefix(c.Subnet).Masked()
}

// Gateway returns the relay's own address in the users' subnet.
func (c *Config) Gateway() netip.Addr {
	return c.SubnetPrefix().Addr().Next()
}
