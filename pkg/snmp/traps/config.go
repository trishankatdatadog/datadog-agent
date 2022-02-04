// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2020-present Datadog, Inc.

package traps

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/gosnmp/gosnmp"
)

// IsEnabled returns whether SNMP trap collection is enabled in the Agent configuration.
func IsEnabled() bool {
	return config.Datadog.GetBool("snmp_traps_enabled")
}

// UserV3 contains the definition of one SNMPv3 user with its username and its auth
// parameters.
// TODO: Add support for EngineID differentiation
type UserV3 struct {
	Username     string `mapstructure:"user" yaml:"user"`
	AuthKey      string `mapstructure:"authKey" yaml:"authKey"`
	AuthProtocol string `mapstructure:"authProtocol" yaml:"authProtocol"`
	PrivKey      string `mapstructure:"privKey" yaml:"privKey"`
	PrivProtocol string `mapstructure:"privProtocol" yaml:"privProtocol"`
}

// Config contains configuration for SNMP trap listeners.
// YAML field tags provided for test marshalling purposes.
// TODO: Add namespace
type Config struct {
	Port                  uint16   `mapstructure:"port" yaml:"port"`
	Users                 []UserV3 `mapstructure:"users" yaml:"users"`
	CommunityStrings      []string `mapstructure:"community_strings" yaml:"community_strings"`
	BindHost              string   `mapstructure:"bind_host" yaml:"bind_host"`
	StopTimeout           int      `mapstructure:"stop_timeout" yaml:"stop_timeout"`
	AuthoritativeEngineID [28]byte `mapstructure:"-" yaml:"-"`
}

// ReadConfig builds and returns configuration from Agent configuration.
func ReadConfig() (*Config, error) {
	var c Config
	err := config.Datadog.UnmarshalKey("snmp_traps_config", &c)
	if err != nil {
		return nil, err
	}

	// gosnmp only supports one v3 user at the moment.
	// TODO: Allow more users
	if len(c.Users) > 1 {
		return nil, errors.New("only one user is currently supported in snmp_traps_config")
	}

	// Set defaults.
	if c.Port == 0 {
		// TODO: The default port 162 cannot be opened in most cases wit the dd-agent user.
		c.Port = defaultPort
	}
	if c.BindHost == "" {
		// Default to global bind_host option.
		// TODO: The default value "localhost" is too restrictive for traps.
		c.BindHost = config.GetBindHost()
	}
	if c.StopTimeout == 0 {
		c.StopTimeout = defaultStopTimeout
	}

	c.AuthoritativeEngineID = c.BuildAuthoritativeEngineID()

	return &c, nil
}

// Addr returns the host:port address to listen on.
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.BindHost, c.Port)
}

func (c *Config) BuildAuthoritativeEngineID() [28]byte {
	engineID := [28]byte{}
	// First byte is always 0x80
	// Next four bytes are the Private Enterprise Number (set to an invalid value here)
	copy(engineID[:5], []byte{0x80, 0xff, 0xff, 0xff, 0xff})
	hostname, err := util.GetHostname(context.TODO())
	if err != nil {
		// this scenario is not likely to happen since
		// the agent cannot start without a hostname
		hostname = "unknown-datadog-agent"
	}
	copy(engineID[5:], []byte(hostname))
	return engineID
}

// BuildV2Params returns a valid GoSNMP SNMPv2 params structure from configuration.
func (c *Config) BuildSNMPParams() (*gosnmp.GoSNMP, error) {
	if len(c.Users) == 0 {
		return &gosnmp.GoSNMP{
			Port:      c.Port,
			Transport: "udp",
			Version:   gosnmp.Version2c, // No user configured, let's user Version2 which is enough and doesn't require setting up fake security data.
			Logger:    gosnmp.NewLogger(&trapLogger{}),
		}, nil
	}
	user := c.Users[0]
	var authProtocol gosnmp.SnmpV3AuthProtocol
	lowerAuthProtocol := strings.ToLower(user.AuthProtocol)
	if lowerAuthProtocol == "" {
		authProtocol = gosnmp.NoAuth
	} else if lowerAuthProtocol == "md5" {
		authProtocol = gosnmp.MD5
	} else if lowerAuthProtocol == "sha" {
		authProtocol = gosnmp.SHA
	} else {
		return nil, fmt.Errorf("unsupported authentication protocol: %s", user.AuthProtocol)
	}

	var privProtocol gosnmp.SnmpV3PrivProtocol
	lowerPrivProtocol := strings.ToLower(user.PrivProtocol)
	if lowerPrivProtocol == "" {
		privProtocol = gosnmp.NoPriv
	} else if lowerPrivProtocol == "des" {
		privProtocol = gosnmp.DES
	} else if lowerPrivProtocol == "aes" {
		privProtocol = gosnmp.AES
	} else if lowerPrivProtocol == "aes192" {
		privProtocol = gosnmp.AES192
	} else if lowerPrivProtocol == "aes192c" {
		privProtocol = gosnmp.AES192C
	} else if lowerPrivProtocol == "aes256" {
		privProtocol = gosnmp.AES256
	} else if lowerPrivProtocol == "aes256c" {
		privProtocol = gosnmp.AES256C
	} else {
		return nil, fmt.Errorf("unsupported privacy protocol: %s", user.PrivProtocol)
	}

	msgFlags := gosnmp.NoAuthNoPriv
	if user.PrivKey != "" {
		msgFlags = gosnmp.AuthPriv
	} else if user.AuthKey != "" {
		msgFlags = gosnmp.AuthNoPriv
	}

	return &gosnmp.GoSNMP{
		Port:          c.Port,
		Transport:     "udp",
		Version:       gosnmp.Version3, // Always using version3 for traps, only option that works with all SNMP versions simultaneously
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      msgFlags,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 user.Username,
			AuthoritativeEngineID:    string(c.AuthoritativeEngineID[:]),
			AuthenticationProtocol:   authProtocol,
			AuthenticationPassphrase: user.AuthKey,
			PrivacyProtocol:          privProtocol,
			PrivacyPassphrase:        user.PrivKey,
		},
		Logger: gosnmp.NewLogger(&trapLogger{}),
	}, nil
}
