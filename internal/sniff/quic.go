package sniff

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

const (
	quicV1 = 0x00000001
	quicV2 = 0x6b3343cf
)

var (
	saltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	saltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

// QUIC collects client Initial packets of one QUIC connection and
// reassembles the ClientHello from their CRYPTO frames (Chrome splits and
// reorders them, and a post-quantum ClientHello spans two packets).
type QUIC struct {
	chunks map[uint64][]byte
	last   Result
}

// IsQUICInitial reports whether a datagram starts with a QUIC v1/v2 Initial.
func IsQUICInitial(b []byte) bool {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return false
	}
	switch binary.BigEndian.Uint32(b[1:5]) {
	case quicV1:
		return b[0]&0x30 == 0x00
	case quicV2:
		return b[0]&0x30 == 0x10
	}
	return false
}

// Add feeds one datagram. It returns ErrNeedMore while the ClientHello is
// incomplete, ErrUnknown for non-QUIC data. Result() then holds what was
// found so far.
func (q *QUIC) Add(dgram []byte) (Result, error) {
	if !IsQUICInitial(dgram) {
		return q.last, ErrUnknown
	}
	payload, err := openInitial(dgram)
	if err != nil {
		return q.last, ErrUnknown
	}
	if q.chunks == nil {
		q.chunks = map[uint64][]byte{}
	}
	if !cryptoFrames(payload, q.chunks) {
		return q.last, ErrUnknown
	}
	// Assemble the contiguous prefix of the crypto stream.
	offs := make([]uint64, 0, len(q.chunks))
	for o := range q.chunks {
		offs = append(offs, o)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	var stream []byte
	for _, o := range offs {
		c := q.chunks[o]
		end := o + uint64(len(c))
		cur := uint64(len(stream))
		if o > cur {
			break
		}
		if end > cur {
			stream = append(stream, c[cur-o:]...)
		}
	}
	r, err := ClientHello(stream)
	r.Protocol = "quic"
	q.last = r
	return r, err
}

// Result returns the latest (possibly partial) result.
func (q *QUIC) Result() Result { return q.last }

// openInitial removes header protection and decrypts the first packet of
// a datagram.
func openInitial(b []byte) ([]byte, error) {
	version := binary.BigEndian.Uint32(b[1:5])
	p := parser{b: b[5:]}
	dcid := p.bytes(p.u8())
	p.skip(p.u8()) // scid
	p.skip(int(p.varint()))
	length := int(p.varint())
	if p.short || length > len(p.b) || length < 20 {
		return nil, ErrUnknown
	}
	pnOff := len(b) - len(p.b)

	salt, kl, il, hl := saltV1, "quic key", "quic iv", "quic hp"
	if version == quicV2 {
		salt, kl, il, hl = saltV2, "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, err
	}
	client := expandLabel(initial, "client in", 32)
	key := expandLabel(client, kl, 16)
	iv := expandLabel(client, il, 12)
	hp := expandLabel(client, hl, 16)

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	if pnOff+4+16 > len(b) {
		return nil, ErrUnknown
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], b[pnOff+4:pnOff+4+16])

	hdr := make([]byte, pnOff+4)
	copy(hdr, b[:pnOff+4])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&3) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOff+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOff+i])
	}
	hdr = hdr[:pnOff+pnLen]

	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct := b[pnOff+pnLen : pnOff+length]
	return aead.Open(nil, nonce, ct, hdr)
}

func expandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, _ := hkdf.Expand(sha256.New, secret, string(info), n)
	return out
}

// cryptoFrames collects CRYPTO frame data by offset. false on frames
// that cannot appear in a client Initial.
func cryptoFrames(b []byte, chunks map[uint64][]byte) bool {
	p := parser{b: b}
	for p.ok() {
		switch t := p.varint(); t {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK
			p.varint()
			p.varint()
			n := p.varint()
			p.varint()
			for i := uint64(0); i < n && !p.short; i++ {
				p.varint()
				p.varint()
			}
			if t == 0x03 {
				p.varint()
				p.varint()
				p.varint()
			}
		case 0x06: // CRYPTO
			off := p.varint()
			data := p.bytes(int(p.varint()))
			if p.short || off > 1<<16 {
				return false
			}
			chunks[off] = append([]byte(nil), data...)
		case 0x1c: // CONNECTION_CLOSE
			return true
		default:
			return false
		}
	}
	return !p.short
}

func (p *parser) varint() uint64 {
	f := p.bytes(1)
	if f == nil {
		return 0
	}
	n := 1 << (f[0] >> 6)
	v := uint64(f[0] & 0x3f)
	rest := p.bytes(n - 1)
	if rest == nil && n > 1 {
		return 0
	}
	for _, c := range rest {
		v = v<<8 | uint64(c)
	}
	return v
}
