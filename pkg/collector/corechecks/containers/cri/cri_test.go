// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build cri
// +build cri

package cri

import (
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/aggregator/mocksender"
	core "github.com/DataDog/datadog-agent/pkg/collector/corechecks"
	"github.com/DataDog/datadog-agent/pkg/config"
	containers "github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/containers/cri/crimock"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

type generateMetricsTest struct {
	name        string
	stats       *pb.ContainerStats
	status      *pb.ContainerStatus
	senderCalls []senderCall
}

type senderCall struct {
	method string
	args   []interface{}
}

func TestCriGenerateMetrics(t *testing.T) {
	criCheck := &CRICheck{
		CheckBase: core.NewCheckBase(criCheckName),
		instance: &CRIConfig{
			CollectDisk: true,
		},
	}

	tags := []string{"runtime:fakeruntime"}
	tests := []generateMetricsTest{
		{
			name:  "container running generates metrics",
			stats: &pb.ContainerStats{},
			status: &pb.ContainerStatus{
				State:     pb.ContainerState_CONTAINER_RUNNING,
				StartedAt: time.Now().UnixNano() - int64(42*time.Second),
			},
			senderCalls: []senderCall{
				{"Gauge", []interface{}{"cri.mem.rss", float64(0), "", tags}},
				{"Rate", []interface{}{"cri.cpu.usage", float64(0), "", tags}},
				{"Gauge", []interface{}{"cri.disk.used", float64(0), "", tags}},
				{"Gauge", []interface{}{"cri.disk.inodes", float64(0), "", tags}},
				{"Gauge", []interface{}{"cri.uptime", mock.MatchedBy(func(uptime float64) bool { return uptime >= 42.0 }), "", tags}},
			},
		},
		{
			name:  "container not running does not generate metrics",
			stats: &pb.ContainerStats{},
			status: &pb.ContainerStatus{
				State: pb.ContainerState_CONTAINER_EXITED,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const cid = "cri://foobar"

			var err error
			criCheck.filter, err = containers.GetSharedMetricFilter()
			defer containers.ResetSharedFilter()

			require.NoError(t, err)

			stats := map[string]*pb.ContainerStats{
				cid: tt.stats,
			}

			mockedCriUtil := new(crimock.MockCRIClient)
			mockedCriUtil.On("GetContainerStatus", cid).Return(tt.status, nil)

			mockedSender := mocksender.NewMockSender(criCheck.ID())
			for _, call := range tt.senderCalls {
				mockedSender.On(call.method, call.args...)
			}

			criCheck.generateMetrics(mockedSender, stats, mockedCriUtil)

			mock.AssertExpectationsForObjects(t, mockedCriUtil, mockedSender)
		})
	}

}

func TestExcludedContainers(t *testing.T) {
	criCheck := &CRICheck{
		CheckBase: core.NewCheckBase(criCheckName),
		instance: &CRIConfig{
			CollectDisk: true,
		},
	}

	ctr := &pb.ContainerStatus{
		Labels:   map[string]string{"io.kubernetes.pod.namespace": "foo-ns"},
		Image:    &pb.ImageSpec{Image: "foo-image"},
		Metadata: &pb.ContainerMetadata{Name: "foo-name"},
	}

	pauseCtr := &pb.ContainerStatus{
		Labels:   map[string]string{"io.kubernetes.container.name": "POD"},
		Image:    &pb.ImageSpec{Image: "pod"},
		Metadata: &pb.ContainerMetadata{Name: "pod"},
	}

	// Namespace based exclusion
	config.Datadog.Set("container_exclude", "kube_namespace:foo*")
	containers.ResetSharedFilter()
	criCheck.filter, _ = containers.GetSharedMetricFilter()
	require.True(t, criCheck.isExcluded(ctr))

	// Container name based exclusion
	config.Datadog.Set("container_exclude", "name:foo*")
	containers.ResetSharedFilter()
	criCheck.filter, _ = containers.GetSharedMetricFilter()
	require.True(t, criCheck.isExcluded(ctr))

	// Image based exclusion
	config.Datadog.Set("container_exclude", "image:foo*")
	containers.ResetSharedFilter()
	criCheck.filter, _ = containers.GetSharedMetricFilter()
	require.True(t, criCheck.isExcluded(ctr))

	// Pause container exclusion
	require.True(t, criCheck.isExcluded(pauseCtr))

	// Container not excluded
	config.Datadog.Set("container_exclude", "image:bar* name:bar* kube_namespace:bar*")
	containers.ResetSharedFilter()
	criCheck.filter, _ = containers.GetSharedMetricFilter()
	require.False(t, criCheck.isExcluded(ctr))
}
