// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build containerd
// +build containerd

package containerd

import (
	"fmt"
	"strconv"
	"time"

	wstats "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	v1 "github.com/containerd/cgroups/stats/v1"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/typeurl"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/DataDog/datadog-agent/pkg/config"
	cutil "github.com/DataDog/datadog-agent/pkg/util/containerd"
	"github.com/DataDog/datadog-agent/pkg/util/containers/v2/metrics/provider"
	"github.com/DataDog/datadog-agent/pkg/util/pointer"
	"github.com/DataDog/datadog-agent/pkg/util/system"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
)

const (
	containerdCollectorID = "containerd"

	pidCacheGCInterval     = 60 * time.Second
	pidCacheFullRefreshKey = "refreshTime"
)

func init() {
	provider.GetProvider().RegisterCollector(provider.CollectorMetadata{
		ID:       containerdCollectorID,
		Priority: 1, // Less than the "system" collector, so we can rely on cgroups directly if possible
		Runtimes: []string{provider.RuntimeNameContainerd},
		Factory: func() (provider.Collector, error) {
			return newContainerdCollector()
		},
		DelegateCache: true,
	})
}

type containerdCollector struct {
	client            cutil.ContainerdItf
	workloadmetaStore workloadmeta.Store
	pidCache          *provider.Cache
}

func newContainerdCollector() (*containerdCollector, error) {
	if !config.IsFeaturePresent(config.Containerd) {
		return nil, provider.ErrPermaFail
	}

	client, err := cutil.NewContainerdUtil()
	if err != nil {
		return nil, provider.ConvertRetrierErr(err)
	}

	return &containerdCollector{
		client:            client,
		workloadmetaStore: workloadmeta.GetGlobalStore(),
		pidCache:          provider.NewCache(pidCacheGCInterval),
	}, nil
}

// ID returns the collector ID.
func (c *containerdCollector) ID() string {
	return containerdCollectorID
}

// GetContainerStats returns stats by container ID.
func (c *containerdCollector) GetContainerStats(containerID string, cacheValidity time.Duration) (*provider.ContainerStats, error) {
	namespace, err := c.containerNamespace(containerID)
	if err != nil {
		return nil, err
	}
	c.client.SetCurrentNamespace(namespace)

	metrics, err := c.getContainerdMetrics(containerID)
	if err != nil {
		return nil, err
	}

	switch metricsVal := metrics.(type) {
	case *v1.Metrics:
		container, err := c.client.Container(containerID)
		if err != nil {
			return nil, fmt.Errorf("could not get container with ID %s: %s", containerID, err)
		}

		OCISpec, err := c.client.Spec(container)
		if err != nil {
			return nil, fmt.Errorf("could not retrieve OCI Spec from container with ID %s: %s", containerID, err)
		}

		info, err := c.client.Info(container)
		if err != nil {
			return nil, fmt.Errorf("could not retrieve the metadata of the container with ID %s: %s", containerID, err)
		}

		processes, err := c.client.TaskPids(container)
		if err != nil {
			return nil, fmt.Errorf("could not retrieve the processes of the container with ID %s: %s", containerID, err)
		}

		return getContainerdStatsLinux(metricsVal, info, OCISpec, processes), nil
	case *wstats.Statistics:
		windowsMetrics := metricsVal.GetWindows()

		if windowsMetrics == nil {
			return nil, fmt.Errorf("error getting Windows metrics for container with ID: %s: %s", containerID, err)
		}

		return getContainerdStatsWindows(windowsMetrics), nil
	default:
		return nil, fmt.Errorf("can't convert the metrics data (type %T) from container with ID %s", metricsVal, containerID)
	}
}

// GetContainerNetworkStats returns network stats by container ID.
func (c *containerdCollector) GetContainerNetworkStats(containerID string, cacheValidity time.Duration) (*provider.ContainerNetworkStats, error) {
	namespace, err := c.containerNamespace(containerID)
	if err != nil {
		return nil, err
	}
	c.client.SetCurrentNamespace(namespace)

	metrics, err := c.getContainerdMetrics(containerID)
	if err != nil {
		return nil, err
	}

	switch metricsVal := metrics.(type) {
	case *v1.Metrics:
		return getContainerdNetworkStatsLinux(metricsVal.Network), nil
	case *wstats.Statistics:
		// Network stats are not available on Windows
		return nil, nil
	default:
		return nil, fmt.Errorf("can't convert the metrics data (type %T) from container with ID %s", metricsVal, containerID)
	}
}

// GetContainerIDForPID returns the container ID for given PID
func (c *containerdCollector) GetContainerIDForPID(pid int, cacheValidity time.Duration) (string, error) {
	currentTime := time.Now()
	strPid := strconv.Itoa(pid)

	cID, found, _ := c.pidCache.Get(currentTime, strPid, cacheValidity)
	if found {
		return cID.(string), nil
	}

	// If we've done a full refresh within cacheValidity, we do not trigger another full refresh
	_, found, _ = c.pidCache.Get(currentTime, pidCacheFullRefreshKey, cacheValidity)
	if found {
		return "", nil
	}

	// Full refresh
	containers, err := c.client.Containers()
	if err != nil {
		return "", err
	}

	c.pidCache.Store(currentTime, pidCacheFullRefreshKey, struct{}{}, nil)
	for _, container := range containers {
		_, _ = c.getPIDs(currentTime, container)
	}

	// Use harcoded cacheValidity as input one could be 0
	cID, found, _ = c.pidCache.Get(currentTime, strPid, time.Second)
	if found {
		return cID.(string), nil
	}

	return "", nil
}

// GetSelfContainerID returns current process container ID
func (c *containerdCollector) GetSelfContainerID() (string, error) {
	// Not available
	return "", nil
}

// This method returns interface{} because the metrics could be an instance of
// v1.Metrics (for Linux) or stats.Statistics (Windows) and they don't share a
// common interface.
func (c *containerdCollector) getContainerdMetrics(containerID string) (interface{}, error) {
	container, err := c.client.Container(containerID)
	if err != nil {
		return nil, fmt.Errorf("could not get container with ID %s: %s", containerID, err)
	}

	metricTask, errTask := c.client.TaskMetrics(container)
	if errTask != nil {
		return nil, fmt.Errorf("could not get metrics for container with ID %s: %s", containerID, err)
	}

	metrics, err := typeurl.UnmarshalAny(metricTask.Data)
	if err != nil {
		return nil, fmt.Errorf("could not convert the metrics data from container with ID %s: %s", containerID, err)
	}

	return metrics, nil
}

func (c *containerdCollector) containerNamespace(containerID string) (string, error) {
	container, err := c.workloadmetaStore.GetContainer(containerID)
	if err != nil {
		return "", err
	}

	return container.Namespace, nil
}

func (c *containerdCollector) getPIDs(currentTime time.Time, container containerd.Container) ([]containerd.ProcessInfo, error) {
	processes, err := c.client.TaskPids(container)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve the processes of the container with ID %s: %s", container.ID(), err)
	}

	for _, process := range processes {
		c.pidCache.Store(currentTime, strconv.FormatUint(uint64(process.Pid), 10), container.ID(), nil)
	}
	return processes, nil
}

func getContainerdStatsLinux(metrics *v1.Metrics, container containers.Container, OCISpec *oci.Spec, processes []containerd.ProcessInfo) *provider.ContainerStats {
	if metrics == nil {
		return nil
	}

	currentTime := time.Now()

	return &provider.ContainerStats{
		Timestamp: currentTime,
		CPU:       getContainerdCPUStatsLinux(metrics.CPU, currentTime, container.CreatedAt, OCISpec),
		Memory:    getContainerdMemoryStatsLinux(metrics.Memory),
		IO:        getContainerdIOStatsLinux(metrics.Blkio, processes),
	}
}

func getContainerdCPUStatsLinux(cpuStat *v1.CPUStat, currentTime time.Time, startTime time.Time, OCISpec *oci.Spec) *provider.ContainerCPUStats {
	if cpuStat == nil {
		return nil
	}

	res := provider.ContainerCPUStats{}

	if cpuStat.Usage != nil {
		res.Total = pointer.UIntToFloatPtr(cpuStat.Usage.Total)
		res.System = pointer.UIntToFloatPtr(cpuStat.Usage.Kernel)
		res.User = pointer.UIntToFloatPtr(cpuStat.Usage.User)
	}

	if cpuStat.Throttling != nil {
		res.ThrottledPeriods = pointer.UIntToFloatPtr(cpuStat.Throttling.ThrottledPeriods)
		res.ThrottledTime = pointer.UIntToFloatPtr(cpuStat.Throttling.ThrottledTime)
	}

	res.Limit = getContainerdCPULimit(currentTime, startTime, OCISpec)

	return &res
}

func getContainerdMemoryStatsLinux(memStat *v1.MemoryStat) *provider.ContainerMemStats {
	if memStat == nil {
		return nil
	}

	res := provider.ContainerMemStats{
		RSS:   pointer.UIntToFloatPtr(memStat.RSS),
		Cache: pointer.UIntToFloatPtr(memStat.Cache),
	}

	if memStat.Usage != nil {
		res.UsageTotal = pointer.UIntToFloatPtr(memStat.Usage.Usage)
		res.Limit = pointer.UIntToFloatPtr(memStat.Usage.Limit)
	}

	if memStat.Kernel != nil {
		res.KernelMemory = pointer.UIntToFloatPtr(memStat.Kernel.Usage)
	}

	if memStat.Swap != nil {
		res.Swap = pointer.UIntToFloatPtr(memStat.Swap.Usage)
	}

	return &res
}

func getContainerdIOStatsLinux(blkioStat *v1.BlkIOStat, processes []containerd.ProcessInfo) *provider.ContainerIOStats {
	if blkioStat == nil {
		return nil
	}

	result := provider.ContainerIOStats{
		ReadBytes:       pointer.Float64Ptr(0),
		WriteBytes:      pointer.Float64Ptr(0),
		ReadOperations:  pointer.Float64Ptr(0),
		WriteOperations: pointer.Float64Ptr(0),
		Devices:         make(map[string]provider.DeviceIOStats),
	}

	for _, blkioStatEntry := range blkioStat.IoServiceBytesRecursive {
		deviceName := fmt.Sprintf("%d:%d", blkioStatEntry.Major, blkioStatEntry.Minor)
		device := result.Devices[deviceName]
		switch blkioStatEntry.Op {
		case "Read":
			device.ReadBytes = pointer.Float64Ptr(float64(blkioStatEntry.Value))
		case "Write":
			device.WriteBytes = pointer.Float64Ptr(float64(blkioStatEntry.Value))
		}
		result.Devices[deviceName] = device
	}

	for _, blkioStatEntry := range blkioStat.IoServicedRecursive {
		deviceName := fmt.Sprintf("%d:%d", blkioStatEntry.Major, blkioStatEntry.Minor)
		device := result.Devices[deviceName]
		switch blkioStatEntry.Op {
		case "Read":
			device.ReadOperations = pointer.Float64Ptr(float64(blkioStatEntry.Value))
		case "Write":
			device.WriteOperations = pointer.Float64Ptr(float64(blkioStatEntry.Value))
		}
		result.Devices[deviceName] = device
	}

	for _, device := range result.Devices {
		if device.ReadBytes != nil {
			*result.ReadBytes += *device.ReadBytes
		}
		if device.WriteBytes != nil {
			*result.WriteBytes += *device.WriteBytes
		}
		if device.ReadOperations != nil {
			*result.ReadOperations += *device.ReadOperations
		}
		if device.WriteOperations != nil {
			*result.WriteOperations += *device.WriteOperations
		}
	}

	return &result
}

func getContainerdNetworkStatsLinux(networkStats []*v1.NetworkStat) *provider.ContainerNetworkStats {
	containerNetworkStats := provider.ContainerNetworkStats{
		BytesSent:   pointer.Float64Ptr(0),
		BytesRcvd:   pointer.Float64Ptr(0),
		PacketsSent: pointer.Float64Ptr(0),
		PacketsRcvd: pointer.Float64Ptr(0),
		Interfaces:  make(map[string]provider.InterfaceNetStats),
	}

	for _, stats := range networkStats {
		*containerNetworkStats.BytesSent += float64(stats.TxBytes)
		*containerNetworkStats.BytesRcvd += float64(stats.RxBytes)
		*containerNetworkStats.PacketsSent += float64(stats.TxPackets)
		*containerNetworkStats.PacketsRcvd += float64(stats.RxPackets)

		containerNetworkStats.Interfaces[stats.Name] = provider.InterfaceNetStats{
			BytesSent:   pointer.UIntToFloatPtr(stats.TxBytes),
			BytesRcvd:   pointer.UIntToFloatPtr(stats.RxBytes),
			PacketsSent: pointer.UIntToFloatPtr(stats.TxPackets),
			PacketsRcvd: pointer.UIntToFloatPtr(stats.RxPackets),
		}
	}

	return &containerNetworkStats
}

func getContainerdCPULimit(currentTime time.Time, startTime time.Time, OCISpec *oci.Spec) *float64 {
	timeDiff := float64(currentTime.Sub(startTime).Nanoseconds()) // cpu.total is in nanoseconds

	if timeDiff <= 0 {
		return nil
	}

	var cpuLimits *specs.LinuxCPU
	if OCISpec != nil && OCISpec.Linux != nil && OCISpec.Linux.Resources != nil {
		cpuLimits = OCISpec.Linux.Resources.CPU
	}

	cpuLimitPct := float64(system.HostCPUCount())
	if cpuLimits != nil && cpuLimits.Period != nil && *cpuLimits.Period > 0 && cpuLimits.Quota != nil && *cpuLimits.Quota > 0 {
		cpuLimitPct = float64(*cpuLimits.Quota) / float64(*cpuLimits.Period)
	}

	limit := cpuLimitPct * timeDiff
	return &limit
}

func getContainerdStatsWindows(windowsStats *wstats.WindowsContainerStatistics) *provider.ContainerStats {
	if windowsStats == nil {
		return nil
	}

	return &provider.ContainerStats{
		Timestamp: windowsStats.Timestamp,
		CPU:       getContainerdCPUStatsWindows(windowsStats.Processor),
		Memory:    getContainerdMemoryStatsWindows(windowsStats.Memory),
		IO:        getContainerdIOStatsWindows(windowsStats.Storage),
	}
}

func getContainerdCPUStatsWindows(procStats *wstats.WindowsContainerProcessorStatistics) *provider.ContainerCPUStats {
	if procStats == nil {
		return nil
	}

	return &provider.ContainerCPUStats{
		Total:  pointer.UIntToFloatPtr(procStats.TotalRuntimeNS),
		System: pointer.UIntToFloatPtr(procStats.RuntimeKernelNS),
		User:   pointer.UIntToFloatPtr(procStats.RuntimeUserNS),
	}
}

func getContainerdMemoryStatsWindows(memStats *wstats.WindowsContainerMemoryStatistics) *provider.ContainerMemStats {
	if memStats == nil {
		return nil
	}

	return &provider.ContainerMemStats{
		PrivateWorkingSet: pointer.UIntToFloatPtr(memStats.MemoryUsagePrivateWorkingSetBytes),
		CommitBytes:       pointer.UIntToFloatPtr(memStats.MemoryUsageCommitBytes),
		CommitPeakBytes:   pointer.UIntToFloatPtr(memStats.MemoryUsageCommitPeakBytes),
	}
}

func getContainerdIOStatsWindows(ioStats *wstats.WindowsContainerStorageStatistics) *provider.ContainerIOStats {
	if ioStats == nil {
		return nil
	}

	return &provider.ContainerIOStats{
		ReadBytes:       pointer.UIntToFloatPtr(ioStats.ReadSizeBytes),
		WriteBytes:      pointer.UIntToFloatPtr(ioStats.WriteSizeBytes),
		ReadOperations:  pointer.UIntToFloatPtr(ioStats.ReadCountNormalized),
		WriteOperations: pointer.UIntToFloatPtr(ioStats.WriteCountNormalized),
	}
}
