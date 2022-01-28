//  Unless explicitly stated otherwise all files in this repository are licensed
//  under the Apache License Version 2.0.
//  This product includes software developed at Datadog (https://www.datadoghq.com/).
//  Copyright 2016-present Datadog, Inc.

//go:build !linux
// +build !linux

package ebpftest

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
)

// StartTracing starts capturing the output of the kprobe trace_pipe for the current running process
func StartTracing(t *testing.T, cfg *ebpf.Config) {
	// do nothing
}