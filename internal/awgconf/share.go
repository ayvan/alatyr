package awgconf

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// AmneziaURL encodes a config as an AmneziaVPN "vpn://" key:
// base64url(qCompress(text)), where qCompress is a 4-byte big-endian
// uncompressed length followed by a zlib stream.
func AmneziaURL(conf string) string {
	var buf bytes.Buffer
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(conf)))
	buf.Write(n[:])
	zw, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	zw.Write([]byte(conf))
	zw.Close()
	return "vpn://" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

// DecodeAmneziaURL decodes a "vpn://" key back to config text. Keys exported
// by AmneziaVPN itself carry JSON; the AmneziaWG config is taken from
// containers[].awg.last_config.config then.
func DecodeAmneziaURL(u string) (string, error) {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(u), "vpn://"))
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return "", fmt.Errorf("vpn:// key: %w", err)
	}
	text := raw
	if len(raw) > 4 {
		if zr, err := zlib.NewReader(bytes.NewReader(raw[4:])); err == nil {
			if b, err := io.ReadAll(zr); err == nil {
				text = b
			}
		}
	}
	t := strings.TrimSpace(string(text))
	if !strings.HasPrefix(t, "{") {
		return t, nil
	}
	var doc struct {
		Containers []map[string]json.RawMessage `json:"containers"`
	}
	if err := json.Unmarshal([]byte(t), &doc); err != nil {
		return "", fmt.Errorf("vpn:// key JSON: %w", err)
	}
	for _, c := range doc.Containers {
		for _, key := range []string{"awg", "wireguard"} {
			var proto struct {
				LastConfig string `json:"last_config"`
			}
			if json.Unmarshal(c[key], &proto) != nil || proto.LastConfig == "" {
				continue
			}
			var last struct {
				Config string `json:"config"`
			}
			if json.Unmarshal([]byte(proto.LastConfig), &last) == nil && strings.Contains(last.Config, "[Interface]") {
				return last.Config, nil
			}
		}
	}
	return "", fmt.Errorf("vpn:// key has no AmneziaWG config")
}

// Version guesses the AmneziaWG protocol generation of a config.
func (c *Config) Version() string {
	p := c.Interface.Params
	has := func(keys ...string) bool {
		for _, k := range keys {
			if p[k] != "" {
				return true
			}
		}
		return false
	}
	switch {
	case has("HeaderProtectionKey", "RandomTrailers", "DisableCookies", "ContentPaddingAddition", "RekeyAfterTime"):
		return "AmneziaWG 3.x"
	case has("S3", "S4") || strings.Contains(p["H1"]+p["H2"]+p["H3"]+p["H4"], "-"):
		return "AmneziaWG 2.0"
	case has("I1", "I2", "I3", "I4", "I5"):
		return "AmneziaWG 1.5"
	case has("Jc", "S1", "S2", "H1"):
		return "AmneziaWG 1.0"
	}
	return "WireGuard"
}
