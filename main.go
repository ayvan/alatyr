// Alatyr: an AmneziaWG relay with split routing. It connects to an upstream AmneziaWG server
// entirely in userspace and lets its own AmneziaWG users reach the internet
// through that tunnel.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"alatyr/internal/app"
	"alatyr/internal/awgconf"
	"alatyr/internal/config"
	"alatyr/internal/store"
	"alatyr/internal/web"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to the relay config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("alatyr", version)
		return
	}
	if err := run(*cfgPath); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.Path(cfg.LogFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("log file: %w", err)
		}
		defer f.Close()
		log.SetOutput(io.MultiWriter(os.Stdout, f))
	}
	log.Printf("alatyr %s starting, config %s", version, cfgPath)

	raw, err := os.ReadFile(cfg.Path(cfg.VPN))
	if err != nil {
		return fmt.Errorf("upstream config: %w", err)
	}
	up, err := awgconf.Parse(string(raw))
	if err != nil {
		return fmt.Errorf("upstream config %s: %w", cfg.VPN, err)
	}
	for _, w := range up.Warnings {
		log.Printf("upstream config: %s", w)
	}

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = up.Interface.MTU
	}
	if mtu == 0 {
		mtu = 1280
	}
	dns := cfg.DNS
	if len(dns) == 0 {
		dns = up.Interface.DNS
	}
	if len(dns) == 0 {
		dns = []string{"1.1.1.1", "8.8.8.8"}
	}

	// config.yaml ports/public_host are only the initial defaults; after the
	// first setup the values edited in the web UI (alatyr-data.json) win.
	defaults := store.Settings{PublicHost: cfg.PublicHost, Listeners: map[string]store.Listener{}}
	for proto, port := range cfg.Ports {
		defaults.Listeners[proto] = store.Listener{Port: port}
	}
	// dns (config.yaml or vpn.conf) is the initial resolver for names routed
	// to the tunnel; it is edited in the web UI afterwards.
	st, err := store.Open(cfg.Path(cfg.DataFile), cfg.SubnetPrefix(), defaults, store.DefaultRouting(dns))
	if err != nil {
		return err
	}
	if st.Migrated() {
		log.Printf("imported users and settings from relay-data.json (re-vpnator)")
	}

	a, err := app.New(app.Options{
		Upstream: up,
		Subnet:   cfg.SubnetPrefix(),
		Gateway:  cfg.Gateway(),
		MTU:      mtu,
		Store:    st,
		ListsDir: cfg.Path(cfg.ListsDir),
		Debug:    cfg.LogLevel == "debug",
	})
	if err != nil {
		return err
	}
	defer a.Close()
	log.Printf("routing mode: %s", st.Routing().Mode)

	addr := net.JoinHostPort(cfg.HTTPListen, strconv.Itoa(cfg.HTTPPort))
	srv := &http.Server{
		Addr: addr,
		Handler: web.New(web.Options{Store: st, Relay: a.Relay, Router: a.Router, Lists: a.Lists, Apply: a.Apply,
			DNS: []string{cfg.Gateway().String()}, MTU: mtu}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("web UI: %w", err)
	}
	log.Printf("web UI: http://%s/", addr)
	if !st.HasPassword() {
		log.Printf("open the web UI to set the admin password")
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Printf("received %v, shutting down", s)
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	return nil
}
