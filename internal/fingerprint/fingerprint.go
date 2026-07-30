package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
)

func SHA256(secret string) (full, short string) {
	sum := sha256.Sum256([]byte(secret))
	full = hex.EncodeToString(sum[:])
	if len(full) < 12 {
		return full, full
	}
	return full, full[:12]
}
