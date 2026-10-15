//go:build windows || linux

package evasion

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "fmt"
)

func AESCTRCrypt(data, key []byte) error {
    if len(key) < aes.BlockSize {
        return fmt.Errorf("AES-CTR requires a key of at least %d bytes",
            aes.BlockSize)
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return fmt.Errorf("aes.NewCipher: %w", err)
    }
    iv := key[:aes.BlockSize]
    stream := cipher.NewCTR(block, iv)
    stream.XORKeyStream(data, data)
    return nil
}

func RC4Crypt(data, key []byte) {
    if len(key) == 0 {
        return
    }
    var s [256]byte
    for i := 0; i < 256; i++ {
        s[i] = byte(i)
    }
    j := 0
    for i := 0; i < 256; i++ {
        j = (j + int(s[i]) + int(key[i%len(key)])) & 0xFF
        s[i], s[j] = s[j], s[i]
    }
    i, j := 0, 0
    for k := range data {
        i = (i + 1) & 0xFF
        j = (j + int(s[i])) & 0xFF
        s[i], s[j] = s[j], s[i]
        data[k] ^= s[(int(s[i])+int(s[j]))&0xFF]
    }
}

type MaskKey struct {
    Key  []byte
    Mode string
}

func NewMaskKey(mode string) MaskKey {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        for i := range b {
            b[i] = byte(i*7 + 3)
        }
    }
    return MaskKey{Key: b, Mode: mode}
}