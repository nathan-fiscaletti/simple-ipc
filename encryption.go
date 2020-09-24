package ipc

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
    "io/ioutil"
    "fmt"
)

var encryptionProvider EncryptionProvider

// EncryptionProvider provides an interface for the encryption and
// decryption of data.
type EncryptionProvider interface {
    // Encrypt encrypts plaintext and returns the ciphertext
    Encrypt(plaintext []byte) ([]byte, error)
    // Decrypt decrypts the ciphertext and returns the plaintext
    Decrypt(ciphertext []byte) ([]byte, error)
}

// SetEncryptionProvider sets the current encryption provider to use
// for all data sent over the IPC tunnel.
func SetEncryptionProvider(provider EncryptionProvider) {
    encryptionProvider = provider
}

type EncryptionKey [32]byte

// NewEncryptionKey will create a random 256-bit key to be used for
// encryption. Will return an error if the source of randomness fails.
func NewEncryptionKey() (*EncryptionKey, error) {
    key := [32]byte{}
    _, err := io.ReadFull(rand.Reader, key[:])
    if err != nil {
        return nil, err
    }
    out := EncryptionKey(key)
    return &out, nil
}

// LoadEncryptionKey will load an EncryptionKey from a file.
func LoadEncryptionKey(path string) (*EncryptionKey, error) {
    content, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }

    if len(content) != 32 {
        return nil, fmt.Errorf(
            "invalid key file %s: must be 32 bytes long (256-bits)", 
        path)
    }

    var keybytes [32]byte
    copy(keybytes[:], content[:32])
    key := EncryptionKey(keybytes)
    return &key, nil
}

// WriteToFile writes the EncryptionKey to the specified file path.
func (key *EncryptionKey) WriteToFile(path string) error {
    return ioutil.WriteFile(path, key[:], 0644)
}

// DefaultEncryptionProvider is an implementation of EncryptionProvider
// that provides basic 256-bit AES-GCM encryption.
type DefaultEncryptionProvider struct {
    key *EncryptionKey
}

// NewDefaultEncryptionProvider will instantiate a new default
// EncryptionProvider that will provide basic 256-bit AES-GCM encryption.
func NewDefaultEncryptionProvider(key *EncryptionKey) EncryptionProvider {
    return DefaultEncryptionProvider{
        key: key,
    }
}

// Encrypt will encrypt the plaintext data using the current key and
// return the ciphertext or an error.
func (provider DefaultEncryptionProvider) Encrypt(
    plaintext []byte,
) ([]byte, error) {
    block, err := aes.NewCipher(provider.key[:])
    if err != nil {
        return []byte{}, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return []byte{}, err
    }

    nonce := make([]byte, gcm.NonceSize())

    _, err = io.ReadFull(rand.Reader, nonce)
    if err != nil {
        return []byte{}, err
    }

    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt will decrypt the ciphertext data using the current key and
// return the plaintext or an error.
func (provider DefaultEncryptionProvider) Decrypt(
    ciphertext []byte,
) ([]byte, error) {
    block, err := aes.NewCipher(provider.key[:])
    if err != nil {
        return []byte{}, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return []byte{}, err
    }

    if len(ciphertext) < gcm.NonceSize() {
        return nil, fmt.Errorf("malformed ciphertext")
    }

    return gcm.Open(nil,
        ciphertext[:gcm.NonceSize()],
        ciphertext[gcm.NonceSize():],
        nil,
    )
}

func encrypt(data []byte) ([]byte, error) {
    if encryptionProvider != nil {
        return encryptionProvider.Encrypt(data)
    }

    return data, nil
}

func decrypt(data []byte) ([]byte, error) {
    if encryptionProvider != nil {
        return encryptionProvider.Decrypt(data)
    }

    return data, nil
}