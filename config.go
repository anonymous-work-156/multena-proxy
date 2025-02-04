package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Log struct {
		Level     int  `yaml:"level"`
		LogTokens bool `yaml:"log_tokens"`
	} `yaml:"log"`

	Web struct {
		ProxyPort           int    `yaml:"proxy_port"`   // where clients come to talk to us
		MetricsPort         int    `yaml:"metrics_port"` // for Prometheus-like engine to scrape us
		Host                string `yaml:"host"`
		TLSVerifySkip       bool   `yaml:"tls_verify_skip"`
		TrustedRootCaPath   string `yaml:"trusted_root_ca_path"`
		JwksCertURL         string `yaml:"jwks_cert_url"`
		OAuthGroupName      string `yaml:"oauth_group_name"` // the token claim field name in which to find group membership
		ServiceAccountToken string `yaml:"service_account_token"`
		HeaderContainingJWT string `yaml:"header_containing_jwt"`
	} `yaml:"web"`

	Admin struct {
		LabelStoreKind   string `yaml:"label_store_kind"`   // choose: configmap, mysql
		LabelStoreFile   string `yaml:"label_store_file"`   // base name of label config file (ignored with label_store_kind: mysql)
		GroupBypass      bool   `yaml:"group_bypass"`       // enable or disable admin group bypass
		Group            string `yaml:"group"`              // the name of the admin group
		MagicValueBypass bool   `yaml:"magic_value_bypass"` // enable or disable magic value bypass (ignored with nested configmap structure)
		MagicValue       string `yaml:"magic_value"`        // the magic value which bypasses checks (ignored with nested configmap structure)
	} `yaml:"admin"`

	Dev struct {
		Enabled  bool   `yaml:"enabled"`
		Username string `yaml:"username"`
	} `yaml:"dev"`

	Db struct {
		Enabled      bool   `yaml:"enabled"`
		User         string `yaml:"user"`
		PasswordPath string `yaml:"password_path"`
		Host         string `yaml:"host"`
		Port         int    `yaml:"port"`
		DbName       string `yaml:"dbName"`
		Query        string `yaml:"query"`
		TokenKey     string `yaml:"token_key"`
	} `yaml:"db"`

	Thanos struct {
		PathPrefix                string            `yaml:"path_prefix"`  // the path where this service will be offered
		URL                       string            `yaml:"url"`          // the service we proxy traffic to
		TenantLabel               string            `yaml:"tenant_label"` // the label to enforce values of
		ErrorOnIllegalTenantValue bool              `yaml:"error_on_illegal_tenant_value"`
		UseMutualTLS              bool              `yaml:"use_mutual_tls"`
		Cert                      string            `yaml:"cert"`
		Key                       string            `yaml:"key"`
		Headers                   map[string]string `yaml:"headers"`
		MetricsTenantOptional     []string          `yaml:"metrics_tenant_optional"` // metrics for which its OK to have no tenant label
	} `yaml:"thanos"`

	Loki struct {
		PathPrefix                string            `yaml:"path_prefix"`  // the path where this service will be offered
		URL                       string            `yaml:"url"`          // the service we proxy traffic to
		TenantLabel               string            `yaml:"tenant_label"` // the label to enforce values of
		ErrorOnIllegalTenantValue bool              `yaml:"error_on_illegal_tenant_value"`
		UseMutualTLS              bool              `yaml:"use_mutual_tls"`
		Cert                      string            `yaml:"cert"`
		Key                       string            `yaml:"key"`
		Headers                   map[string]string `yaml:"headers"`
	} `yaml:"loki"`
}

func (a *App) WithConfig() *App {
	yamlFile, err := tryReadFile("/etc/config/config/config.yaml") // expected to be here deployed in a pod (mounted ConfigMap)
	if err == nil {
		log.Info().Msg("Read config file at first potential path.")
	} else {
		yamlFile, err = tryReadFile("./configs/config.yaml") // expected to be here for test cases
		if err == nil {
			log.Info().Msg("Read config file at second potential path.")
		} else {
			log.Fatal().Err(err).Msg("Failed to read config file in second potential path.")
		}
	}

	a.Cfg = &Config{}
	err = yaml.Unmarshal(yamlFile, a.Cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse config file.")
	}

	zerolog.SetGlobalLevel(zerolog.Level(a.Cfg.Log.Level))
	log.Info().Msg("Config is loaded.")
	log.Info().Any("config", a.Cfg).Msg("") // a.Cfg.Thanos.MetricsTenantOptional can be quite long
	return a
}

func (a *App) WithSAT() *App {
	if a.Cfg.Dev.Enabled {
		a.ServiceAccountToken = a.Cfg.Web.ServiceAccountToken
		return a
	}
	sa, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Fatal().Err(err).Msg("Error while reading service account token")
	}
	a.ServiceAccountToken = string(sa)
	return a
}

func (a *App) WithTLSConfig() *App {
	caCert, err := os.ReadFile("/etc/ssl/ca/ca-certificates.crt")
	if err != nil {
		log.Fatal().Err(err).Msg("Error while reading CA certificate")
	}
	log.Trace().Bytes("caCert", caCert).Msg("")

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(caCert); !ok {
		log.Fatal().Msg("Failed to append CA certificate")
	}
	log.Debug().Any("rootCAs", rootCAs).Msg("")

	if a.Cfg.Web.TrustedRootCaPath != "" {
		err := filepath.Walk(a.Cfg.Web.TrustedRootCaPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || strings.Contains(info.Name(), "..") {
				return nil
			}

			certs, err := os.ReadFile(path)
			if err != nil {
				log.Error().Err(err).Msg("Error while reading trusted CA")
				return err
			}
			log.Debug().Str("path", path).Msg("Adding trusted CA")
			certs = append(certs, []byte("\n")...)
			rootCAs.AppendCertsFromPEM(certs)

			return nil
		})
		if err != nil {
			log.Error().Err(err).Msg("Error while traversing directory")
		}
	}

	var certificates []tls.Certificate

	lokiCert, err := tls.LoadX509KeyPair(a.Cfg.Loki.Cert, a.Cfg.Loki.Key)
	if err != nil {
		log.Error().Err(err).Msg("Error while loading loki certificate")
	} else {
		log.Debug().Str("path", a.Cfg.Loki.Cert).Msg("Adding Loki certificate")
		certificates = append(certificates, lokiCert)
	}

	thanosCert, err := tls.LoadX509KeyPair(a.Cfg.Thanos.Cert, a.Cfg.Thanos.Key)
	if err != nil {
		log.Error().Err(err).Msg("Error while loading thanos certificate")
	} else {
		log.Debug().Str("path", a.Cfg.Thanos.Cert).Msg("Adding Thanos certificate")
		certificates = append(certificates, thanosCert)
	}

	config := &tls.Config{
		InsecureSkipVerify: a.Cfg.Web.TLSVerifySkip,
		RootCAs:            rootCAs,
		Certificates:       certificates,
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = config
	return a
}

func (a *App) WithJWKS() *App {
	log.Info().Msg("Init JWKS config")

	jwks, err := keyfunc.NewDefaultCtx(context.Background(), []string{a.Cfg.Web.JwksCertURL}) // Context is used to end the refresh goroutine.
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create a keyfunc from the server's URL")
	}
	log.Info().Str("url", a.Cfg.Web.JwksCertURL).Msg("JWKS URL")
	a.Jwks = jwks
	return a
}
