// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2020-present Datadog, Inc.

package traps

import (
	"strings"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-agent/pkg/util/cache"
	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
)

const mockedHostname = "VeryLongHostnameThatDoesNotFitIntoTheByteArray"

var expectedEngineID = [28]byte{0x80, 0xff, 0xff, 0xff, 0xff, 0x56, 0x65, 0x72, 0x79, 0x4c, 0x6f, 0x6e, 0x67, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x54, 0x68, 0x61, 0x74, 0x44, 0x6f, 0x65}

func setMockedHostname() {
	cacheHostnameKey := cache.BuildAgentKey("hostname")
	cache.Cache.Set(cacheHostnameKey, util.HostnameData{Hostname: mockedHostname}, -1)
}

func TestFullConfig(t *testing.T) {
	setMockedHostname()
	Configure(t, Config{
		Port: 1234,
		Users: []UserV3{
			{
				Username:     "user",
				AuthKey:      "password",
				AuthProtocol: "MD5",
				PrivKey:      "password",
				PrivProtocol: "AES",
			},
		},
		BindHost:         "127.0.0.1",
		CommunityStrings: []string{"public"},
		StopTimeout:      12,
		Namespace:        "foo",
	})
	config, err := ReadConfig()
	assert.NoError(t, err)
	assert.Equal(t, uint16(1234), config.Port)
	assert.Equal(t, 12, config.StopTimeout)
	assert.Equal(t, []string{"public"}, config.CommunityStrings)
	assert.Equal(t, "127.0.0.1", config.BindHost)
	assert.Equal(t, "foo", config.Namespace)
	assert.Equal(t, []UserV3{
		{
			Username:     "user",
			AuthKey:      "password",
			AuthProtocol: "MD5",
			PrivKey:      "password",
			PrivProtocol: "AES",
		},
	}, config.Users)

	params, err := config.BuildSNMPParams()
	assert.NoError(t, err)
	assert.Equal(t, uint16(1234), params.Port)
	assert.Equal(t, gosnmp.Version3, params.Version)
	assert.Equal(t, "udp", params.Transport)
	assert.NotNil(t, params.Logger)
	assert.Equal(t, gosnmp.UserSecurityModel, params.SecurityModel)
	assert.Equal(t, &gosnmp.UsmSecurityParameters{
		UserName:                 "user",
		AuthoritativeEngineID:    string(expectedEngineID[:]),
		AuthenticationProtocol:   gosnmp.MD5,
		AuthenticationPassphrase: "password",
		PrivacyProtocol:          gosnmp.AES,
		PrivacyPassphrase:        "password",
	}, params.SecurityParameters)
}

func TestMinimalConfig(t *testing.T) {
	Configure(t, Config{})
	config, err := ReadConfig()
	assert.NoError(t, err)
	assert.Equal(t, uint16(162), config.Port)
	assert.Equal(t, 5, config.StopTimeout)
	assert.Equal(t, []string{}, config.CommunityStrings)
	assert.Equal(t, "localhost", config.BindHost)
	assert.Equal(t, []UserV3{}, config.Users)
	assert.Equal(t, "default", config.Namespace)

	params, err := config.BuildSNMPParams()
	assert.NoError(t, err)
	assert.Equal(t, uint16(162), params.Port)
	assert.Equal(t, gosnmp.Version2c, params.Version)
	assert.Equal(t, "udp", params.Transport)
	assert.NotNil(t, params.Logger)
	assert.Equal(t, nil, params.SecurityParameters)
}

func TestDefaultUsers(t *testing.T) {
	Configure(t, Config{
		CommunityStrings: []string{"public"},
		StopTimeout:      11,
	})
	config, err := ReadConfig()
	assert.NoError(t, err)

	assert.Equal(t, 11, config.StopTimeout)
}

func TestBuildAuthoritativeEngineID(t *testing.T) {
	setMockedHostname()
	config := Config{}
	engineID := config.BuildAuthoritativeEngineID()
	assert.Equal(t, [28]byte{0x80, 0xff, 0xff, 0xff, 0xff, 0x56, 0x65, 0x72, 0x79, 0x4c, 0x6f, 0x6e, 0x67, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x54, 0x68, 0x61, 0x74, 0x44, 0x6f, 0x65}, engineID)
}

func TestNamespaceIsNormalized(t *testing.T) {
	Configure(t, Config{
		Namespace: "><\n\r\tfoo",
	})

	config, err := ReadConfig()
	assert.NoError(t, err)

	assert.Equal(t, "--foo", config.Namespace)
}

func TestInvalidNamespace(t *testing.T) {
	Configure(t, Config{
		Namespace: strings.Repeat("x", 101),
	})

	_, err := ReadConfig()
	assert.Error(t, err)
}

func TestNamespaceSetGlobally(t *testing.T) {
	ConfigureWithGlobalNamespace(t, Config{}, "foo")

	config, err := ReadConfig()
	assert.NoError(t, err)

	assert.Equal(t, "foo", config.Namespace)
}

func TestNamespaceSetBothGloballyAndLocally(t *testing.T) {
	ConfigureWithGlobalNamespace(t, Config{Namespace: "bar"}, "foo")

	config, err := ReadConfig()
	assert.NoError(t, err)

	assert.Equal(t, "bar", config.Namespace)
}
