// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package metrics

import (
	"encoding/json"
	"fmt"
)

// ServiceCheckStatus represents the status associated with a service check
type ServiceCheckStatus int

// Enumeration of the existing service check statuses, and their values
const (
	ServiceCheckOK       ServiceCheckStatus = iota
	ServiceCheckWarning  ServiceCheckStatus = 1
	ServiceCheckCritical ServiceCheckStatus = 2
	ServiceCheckUnknown  ServiceCheckStatus = 3
)

// GetServiceCheckStatus returns the ServiceCheckStatus from and integer value
func GetServiceCheckStatus(val int) (ServiceCheckStatus, error) {
	switch val {
	case int(ServiceCheckOK):
		return ServiceCheckOK, nil
	case int(ServiceCheckWarning):
		return ServiceCheckWarning, nil
	case int(ServiceCheckCritical):
		return ServiceCheckCritical, nil
	case int(ServiceCheckUnknown):
		return ServiceCheckUnknown, nil
	default:
		return ServiceCheckUnknown, fmt.Errorf("invalid value for a ServiceCheckStatus")
	}
}

// String returns a string representation of ServiceCheckStatus
func (s ServiceCheckStatus) String() string {
	switch s {
	case ServiceCheckOK:
		return "OK"
	case ServiceCheckWarning:
		return "WARNING"
	case ServiceCheckCritical:
		return "CRITICAL"
	case ServiceCheckUnknown:
		return "UNKNOWN"
	default:
		return ""
	}
}

// ServiceCheck holds a service check (w/ serialization to DD api format)
type ServiceCheck struct {
	CheckName   string             `json:"check"`
	Host        string             `json:"host_name"`
	Ts          int64              `json:"timestamp"`
	Status      ServiceCheckStatus `json:"status"`
	Message     string             `json:"message"`
	Tags        []string           `json:"tags"`
	OriginID    string             `json:"-"`
	K8sOriginID string             `json:"-"`
	Cardinality string             `json:"-"`
}

func (sc ServiceCheck) String() string {
	s, err := json.Marshal(sc)
	if err != nil {
		return ""
	}
	return string(s)
}
