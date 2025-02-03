package main

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/fsnotify/fsnotify"
	"github.com/go-sql-driver/mysql"
	"github.com/spf13/viper"
)

// Labelstore represents an interface defining methods for connecting to a
// label store and retrieving labels associated with a given OAuth token.
type Labelstore interface {
	// Connect establishes a connection with the label store using App configuration.
	Connect(App) error
	// GetLabels retrieves labels associated with the provided OAuth token.
	// Returns a map containing the labels and a boolean indicating whether
	// the label is cluster-wide or not.
	GetLabels(token OAuthToken, a *App) ([]string, bool)
}

// WithLabelStore initializes and connects to a LabelStore specified in the
// application configuration. It assigns the connected LabelStore to the App
// instance and returns it. If the LabelStore type is unknown or an error
// occurs during the connection, it logs a fatal error.
func (a *App) WithLabelStore() *App {
	switch a.Cfg.Admin.LabelStoreKind {
	case "configmap":
		a.LabelStore = &ConfigMapHandler{}
	case "mysql":
		a.LabelStore = &MySQLHandler{}
	default:
		log.Fatal().Str("type", a.Cfg.Admin.LabelStoreKind).Msg("Unknown label store type")
	}
	err := a.LabelStore.Connect(*a)
	if err != nil {
		log.Fatal().Err(err).Msg("Error connecting to labelstore")
	}
	return a
}

type InnerNestedLabelConfig struct {
	Name         string   `yaml:"name"`
	FilterValues []string `yaml:"filtervalues"`
	Groups       []string `yaml:"groups"`
}

type NestedLabelConfig struct {
	Admins    []string                 `yaml:"admins"`
	Solutions []InnerNestedLabelConfig `yaml:"solutions"`
}

type ConfigMapHandler struct {
	labels       map[string]map[string]bool
	nestedLabels *NestedLabelConfig
}

func (c *ConfigMapHandler) Connect(a App) error {
	v := viper.New()
	v.SetConfigName(a.Cfg.Admin.LabelStoreFile)
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/config/labels/") // expected to be here deployed in a pod (mounted ConfigMap)
	v.AddConfigPath("./configs")           // expected to be here for test cases

	err := v.MergeInConfig() // unclear why, but it is essential to get actual values loaded into the struct
	if err != nil {
		log.Fatal().Err(err).Msg("Error while unmarshalling label config file")
	}

	err = v.Unmarshal(&c.labels) // try the old 'linear' format
	if err != nil {
		c.nestedLabels = &NestedLabelConfig{}
		err = v.Unmarshal(c.nestedLabels) // try the new 'nested' format
		if err != nil {
			log.Error().Err(err).Msg("Error while unmarshalling label config file")
			return err
		}
	}
	v.OnConfigChange(func(e fsnotify.Event) {
		log.Info().Str("file", e.Name).Msg("Config file changed")
		err = v.Unmarshal(&c.labels)
		if err != nil {
			log.Error().Err(err).Msg("Error while unmarshalling label config file")
			return
		}
		log.Info().Msg("Label config is reloaded.")
	})
	v.WatchConfig()
	log.Info().Msg("Label config is loaded.")
	log.Debug().Any("config", c.labels).Msg("")
	return nil
}

func (c *ConfigMapHandler) GetLabels(token OAuthToken, a *App) ([]string, bool) {
	mergedValues := make(map[string]bool)

	if c.nestedLabels != nil {

		// search for our username or any of our groups in the list of admin users/groups
		for _, entityName := range c.nestedLabels.Admins {

			// check the username against the list of admins
			if entityName == token.PreferredUsername {
				return nil, true
			}

			// check each group against the list of admins
			for _, group := range token.Groups {
				if entityName == group {
					return nil, true
				}
			}
		}

		// search for any of our groups in any of the 'solutions'
		for _, solution := range c.nestedLabels.Solutions {
		startSolution:
			for _, comparisonGroup := range solution.Groups {
				if comparisonGroup == token.PreferredUsername {
					// having found a user match, we grab all the label values and proceed to the next 'solution'
					for _, filterVal := range solution.FilterValues {
						mergedValues[filterVal] = true
					}
					break startSolution
				}

				for _, group := range token.Groups {
					if comparisonGroup == group {
						// having found a group match, we grab all the label values and proceed to the next 'solution'
						for _, filterVal := range solution.FilterValues {
							mergedValues[filterVal] = true
						}
						break startSolution
					}
				}
			}
		}
	} else {
		// NOTE: the config system (Viper) is case-insensitive for keys, which appears to mean it returns lower-case
		// therefore when looking for our user or group(s), which are stored as keys, we downcase them

		for k, v := range c.labels[strings.ToLower(token.PreferredUsername)] {
			if !v {
				continue // pointing a key at false is the same as not including the key at all
			}
			mergedValues[k] = true
			if a != nil && a.Cfg.Admin.MagicValueBypass && k == a.Cfg.Admin.MagicValue {
				return nil, true
			}
		}

		for _, group := range token.Groups {
			for k, v := range c.labels[strings.ToLower(group)] {
				if !v {
					continue // pointing a key at false is the same as not including the key at all
				}
				mergedValues[k] = true
				if a != nil && a.Cfg.Admin.MagicValueBypass && k == a.Cfg.Admin.MagicValue {
					return nil, true
				}
			}
		}
	}

	return MapKeysToArray(mergedValues), false
}

type MySQLHandler struct {
	DB       *sql.DB
	Query    string
	TokenKey string
}

func (m *MySQLHandler) Connect(a App) error {
	m.TokenKey = a.Cfg.Db.TokenKey
	m.Query = a.Cfg.Db.Query
	password, err := os.ReadFile(a.Cfg.Db.PasswordPath)
	if err != nil {
		log.Error().Err(err).Msg("Could not read db password")
		return err
	}
	cfg := mysql.Config{
		User:                 a.Cfg.Db.User,
		Passwd:               string(password),
		Net:                  "tcp",
		AllowNativePasswords: true,
		Addr:                 fmt.Sprintf("%s:%d", a.Cfg.Db.Host, a.Cfg.Db.Port),
		DBName:               a.Cfg.Db.DbName,
	}
	// Get a database handle.
	m.DB, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Error().Err(err).Msg("Error opening DB connection")
		return err
	}
	return nil
}

func (m *MySQLHandler) Close() {
	err := m.DB.Close()
	if err != nil {
		log.Warn().Err(err).Msg("Error closing DB connection")
	}
}

func (m *MySQLHandler) GetLabels(token OAuthToken, a *App) ([]string, bool) {

	// there are three possible values to check using SQL
	tokenMap := map[string]string{
		"email":    token.Email,
		"username": token.PreferredUsername,
		"groups":   strings.Join(token.Groups, ","), // unclear if this has been thought through fully
	}

	// choose one of them according to the setup
	value, ok := tokenMap[m.TokenKey]
	if !ok {
		log.Fatal().Str("property", m.TokenKey).Msg("Unsupported token property") // fatal because its a config error
	}
	n := strings.Count(m.Query, "?")

	var params []any
	for i := 0; i < n; i++ {
		params = append(params, value)
	}

	res, err := m.DB.Query(m.Query, params...)
	defer func(res *sql.Rows) {
		err := res.Close()
		if err != nil {
			log.Warn().Err(err).Msg("Error closing DB result")
		}
	}(res)
	if err != nil {
		log.Error().Err(err).Str("query", m.Query).Msg("Error while querying database")
		return nil, false
	}

	// using a map here may be mostly pointless, but does de-dupe if that is a concern
	labels := make(map[string]bool)

	for res.Next() {
		var label string
		err = res.Scan(&label)
		if err != nil {
			log.Error().Err(err).Msg("Error scanning DB result")
			return nil, false
		}

		// support the magic value for bypassing checks
		if a != nil && a.Cfg.Admin.MagicValueBypass && label == a.Cfg.Admin.MagicValue {
			return nil, true
		}

		// the value being pointed at is not important
		labels[label] = true
	}
	return MapKeysToArray(labels), false
}
