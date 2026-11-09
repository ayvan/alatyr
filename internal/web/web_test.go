package web

import "testing"

func TestFileName(t *testing.T) {
	for in, want := range map[string]string{
		"Вася phone":          "vasya_phone.conf",
		"laptop-petya":        "laptop-petya.conf",
		"очень длинное имя!!": "ochen_dlinnoe_i.conf",
		"???":                 "relay.conf",
	} {
		if got := fileName(in); got != want {
			t.Errorf("fileName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVirtualIface(t *testing.T) {
	for name, want := range map[string]bool{"en0": false, "eth0": false, "Ethernet": false, "Wi-Fi": false,
		"utun4": true, "bridge100": true, "docker0": true, "vEthernet (WSL)": true, "wg0": true} {
		if got := virtualIface(name); got != want {
			t.Errorf("virtualIface(%q) = %v", name, got)
		}
	}
}
