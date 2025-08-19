package main

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func TestCheckNonenforcementHeader(t *testing.T) {
	log.Info().Caller().Msg("Start TestCheckNonenforcementHeader().")
	defer log.Info().Msg("End TestCheckNonenforcementHeader().")

	a := assert.New(t)

	app := &App{}
	app.WithConfig()
	app.Cfg.Admin.HeaderBypass = true
	app.Cfg.Admin.Header.Key = "happyheader"
	app.Cfg.Admin.Header.Value = "happyvalue"

	headers := map[string]string{}
	a.False(checkNonenforcementHeader(headers, app.Cfg))

	headers = map[string]string{"a": "b"}
	a.False(checkNonenforcementHeader(headers, app.Cfg))

	headers = map[string]string{"a": "b", app.Cfg.Admin.Header.Key: "othervalue"}
	a.False(checkNonenforcementHeader(headers, app.Cfg))

	headers = map[string]string{"a": "b", "otherkey": app.Cfg.Admin.Header.Value}
	a.False(checkNonenforcementHeader(headers, app.Cfg))

	headers = map[string]string{"a": "b", app.Cfg.Admin.Header.Key: app.Cfg.Admin.Header.Value}
	a.True(checkNonenforcementHeader(headers, app.Cfg))
}
