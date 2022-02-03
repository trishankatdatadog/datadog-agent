// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package ratelimit

import (
	"errors"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
)

// MemBasedRateLimiter is a rate limiter based on memory usage.
// While the high memory limit is reached, Wait() blocks and try to release memory.
// When the low memory limit is reached, Wait() blocks once and may try to release memory.
// The memory limits are defined as soft limits.
//
// `memoryRateLimiter` provides a way to dynamically update the rate at which the memory limit
// is checked.
// When the soft limit is reached, we would like to wait and release memory but not block too often.
// `freeOSMemoryRateLimiter` provides a way to dynamically update the rate at which `FreeOSMemory` is
// called when the soft limit is reached.
type MemBasedRateLimiter struct {
	telemetry               telemetry
	memoryUsage             memoryUsage
	lowSoftLimitRate        float64
	highSoftLimitRate       float64
	memoryRateLimiter       *geometricRateLimiter
	freeOSMemoryRateLimiter *geometricRateLimiter
	previousMemoryUsageRate float64
}

var memBasedRateLimiterTml = newMemBasedRateLimiterTelemetry()

// BuildMemBasedRateLimiter builds a new instance of *MemBasedRateLimiter
func BuildMemBasedRateLimiter() (*MemBasedRateLimiter, error) {
	memoryUsageRate, err := newProcessMemoryUsage()
	if err != nil {
		return nil, err
	}

	return NewMemBasedRateLimiter(
		memBasedRateLimiterTml,
		memoryUsageRate,
		getConfigFloat("low_soft_limit"),
		getConfigFloat("high_soft_limit"),
		config.Datadog.GetInt("dogstatsd_mem_based_rate_limiter.go_gc"),
		geometricRateLimiterConfig{
			getConfigFloat("rate_check.min"),
			getConfigFloat("rate_check.max"),
			getConfigFloat("rate_check.factor")},
		geometricRateLimiterConfig{
			getConfigFloat("soft_limit_freeos_check.min"),
			getConfigFloat("soft_limit_freeos_check.max"),
			getConfigFloat("soft_limit_freeos_check.factor"),
		},
	)
}

func getConfigFloat(subkey string) float64 {
	return config.Datadog.GetFloat64("dogstatsd_mem_based_rate_limiter." + subkey)
}

// NewMemBasedRateLimiter creates a new instance of MemBasedRateLimiter.
func NewMemBasedRateLimiter(
	telemetry telemetry,
	memoryUsage memoryUsage,
	lowSoftLimitRate float64,
	highSoftLimitRate float64,
	goGC int,
	memoryRateLimiter geometricRateLimiterConfig,
	freeOSMemoryRateLimiter geometricRateLimiterConfig) (*MemBasedRateLimiter, error) {

	// When `SetMemoryLimit` will be available (https://github.com/golang/go/issues/48409),
	//  SetGCPercent, madvdontneed=1 and debug.FreeOSMemory() can be removed.
	if goGC > 0 {
		debug.SetGCPercent(goGC)
	}

	// madvdontneed=1 forces the memory to be released. This allows the RSS to reflect what
	// is really used by the Agent
	if !strings.Contains(os.Getenv("GODEBUG"), "madvdontneed=1") {
		return nil, errors.New("GODEBUG must have `madvdontneed=1` in order to use this feature")
	}

	return &MemBasedRateLimiter{
		telemetry:               telemetry,
		memoryUsage:             memoryUsage,
		lowSoftLimitRate:        lowSoftLimitRate,
		highSoftLimitRate:       highSoftLimitRate,
		memoryRateLimiter:       newGeometricRateLimiter(memoryRateLimiter),
		freeOSMemoryRateLimiter: newGeometricRateLimiter(freeOSMemoryRateLimiter),
	}, nil
}

// Wait and try to release the memory. See MemBasedRateLimiter for more information.
func (m *MemBasedRateLimiter) Wait() error {
	if !m.memoryRateLimiter.keep() {
		m.telemetry.incNoWait()
		return nil
	}
	m.telemetry.incWait()

	rate, err := m.memoryUsage.rate()
	if err != nil {
		return err
	}
	m.telemetry.setMemoryUsageRate(rate)
	if rate > m.previousMemoryUsageRate {
		m.memoryRateLimiter.increaseRate()
	} else {
		m.memoryRateLimiter.decreaseRate()
	}

	if rate, err = m.waitWhileHighLimit(rate); err != nil {
		return nil
	}

	m.waitOnceLowLimit(rate)
	m.previousMemoryUsageRate = rate
	return nil
}

func (m *MemBasedRateLimiter) waitWhileHighLimit(rate float64) (float64, error) {
	for rate > m.highSoftLimitRate {
		m.telemetry.incHighLimit()
		debug.FreeOSMemory()
		time.Sleep(100 * time.Millisecond)
		var err error
		if rate, err = m.memoryUsage.rate(); err != nil {
			return 0, err
		}
	}
	return rate, nil
}

func (m *MemBasedRateLimiter) waitOnceLowLimit(rate float64) {
	if rate > m.lowSoftLimitRate {
		m.telemetry.incLowLimit()
		if m.freeOSMemoryRateLimiter.keep() {
			debug.FreeOSMemory()
			m.telemetry.incLowLimitFreeOSMemory()
		} else {
			time.Sleep(1 * time.Millisecond)
		}

		if rate > m.previousMemoryUsageRate {
			m.freeOSMemoryRateLimiter.increaseRate()
		} else {
			m.freeOSMemoryRateLimiter.decreaseRate()
		}
	}
}
