// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build functionaltests && linux_bpf
// +build functionaltests,linux_bpf

package tests

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/security/probe"
	"github.com/DataDog/datadog-agent/pkg/security/probe/constantfetch"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
	"github.com/stretchr/testify/assert"
)

func TestFallbackConstants(t *testing.T) {
	test, err := newTestModule(t, nil, []*rules.RuleDefinition{}, testOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	kv, err := test.probe.GetKernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	config := test.config

	fallbackFetcher := constantfetch.NewFallbackConstantFetcher(kv)
	rcFetcher := constantfetch.NewRuntimeCompilationConstantFetcher(&config.Config, nil)

	fallbackConstants, err := probe.GetOffsetConstantsFromFetcher(fallbackFetcher)
	if err != nil {
		t.Error(err)
	}

	rcConstants, err := probe.GetOffsetConstantsFromFetcher(rcFetcher)
	if err != nil {
		t.Error(err)
	}

	if !assert.Equal(t, fallbackConstants, rcConstants) {
		kernelVersion, err := test.probe.GetKernelVersion()
		if err != nil {
			t.Error("failed to get probe kernel version")
		} else {
			t.Logf("kernel version: %v", kernelVersion)
		}
	}
}
