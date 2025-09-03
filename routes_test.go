package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckNonenforcementHeader(t *testing.T) {
	a := assert.New(t)

	app := &App{}
	app.WithConfig()
	app.Cfg.Admin.HeaderBypass.Enabled = true
	app.Cfg.Admin.HeaderBypass.Key = "HappyHeader"
	app.Cfg.Admin.HeaderBypass.Value = "happyvalue"

	req, _ := http.NewRequest("GET", "/some/api", nil)
	skip := checkBypassHeader(req, app) // no headers
	a.False(skip)

	req.Header.Add("a", "b")
	skip = checkBypassHeader(req, app) // some unrelated header
	a.False(skip)

	req.Header.Add(app.Cfg.Admin.HeaderBypass.Key, "othervalue") // right key, wrong value
	skip = checkBypassHeader(req, app)
	a.False(skip)

	req.Header.Add("otherkey", app.Cfg.Admin.HeaderBypass.Value) // wrong key, right value
	skip = checkBypassHeader(req, app)
	a.False(skip)

	req, _ = http.NewRequest("GET", "/some/api", nil)
	req.Header.Add(app.Cfg.Admin.HeaderBypass.Key, app.Cfg.Admin.HeaderBypass.Value) // right
	skip = checkBypassHeader(req, app)
	a.True(skip)

	req.Header.Add("a", "b")
	skip = checkBypassHeader(req, app) // some unrelated header
	a.True(skip)
}

// Encrypt encrypts plaintext with a 32-byte key and returns base64 string
func encryptGroupHeaderForTesting(plaintext string, key []byte) (string, error) {
	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt and combine nonce + ciphertext
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Return as base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func TestCheckGroupHeader(t *testing.T) {
	a := assert.New(t)

	// generate two random 32-byte keys
	key := make([]byte, 32)
	badkey := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		panic(err)
	}
	_, err = io.ReadFull(rand.Reader, badkey)
	if err != nil {
		panic(err)
	}
	base64Key := base64.StdEncoding.EncodeToString(key)

	app := &App{}
	app.WithConfig()
	app.Cfg.Web.GroupFromHeader.Enabled = true
	app.Cfg.Web.GroupFromHeader.Name = "GroupsDefinedHere"
	app.GroupFromHeaderEncryptionKey = base64Key

	// send something not base64-encoded
	groupHeaderVal := "invalid"
	req, _ := http.NewRequest("GET", "/some/api", nil)
	req.Header.Add(app.Cfg.Web.GroupFromHeader.Name, groupHeaderVal)
	groups := checkGroupHeader(req, app)
	a.Nil(groups)

	// send something that is base64-encoded, but is not encrypted
	groupHeaderVal = base64.StdEncoding.EncodeToString([]byte("invalid"))
	req, _ = http.NewRequest("GET", "/some/api", nil)
	req.Header.Add(app.Cfg.Web.GroupFromHeader.Name, groupHeaderVal)
	groups = checkGroupHeader(req, app)
	a.Nil(groups)

	// send something that is base64-encoded and encrypted with a fine payload but the wrong encryption key
	groupHeaderVal, err = encryptGroupHeaderForTesting("test_group", badkey)
	if err != nil {
		panic(err)
	}
	req, _ = http.NewRequest("GET", "/some/api", nil)
	req.Header.Add(app.Cfg.Web.GroupFromHeader.Name, groupHeaderVal)
	groups = checkGroupHeader(req, app)
	a.Nil(groups)

	// send something that should work
	groupHeaderVal, err = encryptGroupHeaderForTesting("test_group", key)
	if err != nil {
		panic(err)
	}
	req, _ = http.NewRequest("GET", "/some/api", nil)
	req.Header.Add(app.Cfg.Web.GroupFromHeader.Name, groupHeaderVal)
	groups = checkGroupHeader(req, app)
	a.EqualValues([]string{"test_group"}, groups)
}
