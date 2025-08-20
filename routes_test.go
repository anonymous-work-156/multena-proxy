package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckNonenforcementHeader(t *testing.T) {
	a := assert.New(t)

	app := &App{}
	app.WithConfig()
	app.Cfg.Admin.HeaderBypass = true
	app.Cfg.Admin.Header.Key = "HappyHeader"
	app.Cfg.Admin.Header.Value = "happyvalue"

	req, _ := http.NewRequest("GET", "/some/api", nil)
	a.False(checkNonenforcementHeader(req, app.Cfg)) // no headers

	req.Header.Add("a", "b")
	a.False(checkNonenforcementHeader(req, app.Cfg)) // some unrelated header

	req.Header.Add(app.Cfg.Admin.Header.Key, "othervalue") // right key, wrong value
	a.False(checkNonenforcementHeader(req, app.Cfg))

	req.Header.Add("otherkey", app.Cfg.Admin.Header.Value) // wrong key, right value
	a.False(checkNonenforcementHeader(req, app.Cfg))

	req, _ = http.NewRequest("GET", "/some/api", nil)
	req.Header.Add(app.Cfg.Admin.Header.Key, app.Cfg.Admin.Header.Value) // right
	a.True(checkNonenforcementHeader(req, app.Cfg))

	req.Header.Add("a", "b")
	a.True(checkNonenforcementHeader(req, app.Cfg)) // some unrelated header
}
