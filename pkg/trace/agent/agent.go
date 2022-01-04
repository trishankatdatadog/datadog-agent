// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package agent

import (
	"context"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/DataDog/datadog-agent/pkg/obfuscate"
	"github.com/DataDog/datadog-agent/pkg/trace/api"
	"github.com/DataDog/datadog-agent/pkg/trace/config"
	"github.com/DataDog/datadog-agent/pkg/trace/config/features"
	"github.com/DataDog/datadog-agent/pkg/trace/event"
	"github.com/DataDog/datadog-agent/pkg/trace/filters"
	"github.com/DataDog/datadog-agent/pkg/trace/info"
	"github.com/DataDog/datadog-agent/pkg/trace/metrics"
	"github.com/DataDog/datadog-agent/pkg/trace/metrics/timing"
	"github.com/DataDog/datadog-agent/pkg/trace/pb"
	"github.com/DataDog/datadog-agent/pkg/trace/sampler"
	"github.com/DataDog/datadog-agent/pkg/trace/stats"
	"github.com/DataDog/datadog-agent/pkg/trace/traceutil"
	"github.com/DataDog/datadog-agent/pkg/trace/writer"
	"github.com/DataDog/datadog-agent/pkg/util/fargate"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	// inferredSpanTagSourceKey is the key to the meta tag that lets us know whether this span should inherit its tags.
	// Expected options are "lambda" and "self"
	inferredSpanTagSourceKey = "_inferred_span.tag_source"
	// inferredSpanTagSourceSelf
	inferredSpanTagSourceSelf = "self"
	// tagHostname specifies the hostname of the tracer.
	// DEPRECATED: Tracer hostname is now specified as a TracerPayload field.
	tagHostname = "_dd.hostname"
)

// Agent struct holds all the sub-routines structs and make the data flow between them
type Agent struct {
	Receiver              *api.HTTPReceiver
	OTLPReceiver          *api.OTLPReceiver
	Concentrator          *stats.Concentrator
	ClientStatsAggregator *stats.ClientStatsAggregator
	Blacklister           *filters.Blacklister
	Replacer              *filters.Replacer
	PrioritySampler       *sampler.PrioritySampler
	ErrorsSampler         *sampler.ErrorsSampler
	RareSampler           *sampler.RareSampler
	NoPrioritySampler     *sampler.NoPrioritySampler
	EventProcessor        *event.Processor
	TraceWriter           *writer.TraceWriter
	StatsWriter           *writer.StatsWriter

	// obfuscator is used to obfuscate sensitive data from various span
	// tags based on their type.
	obfuscator     *obfuscate.Obfuscator
	cardObfuscator *ccObfuscator

	// ModifySpan will be called on all spans, if non-nil.
	ModifySpan func(*pb.Span)

	// In takes incoming payloads to be processed by the agent.
	In chan *api.Payload

	// config
	conf *config.AgentConfig

	// Used to synchronize on a clean exit
	ctx context.Context
}

// NewAgent returns a new Agent object, ready to be started. It takes a context
// which may be cancelled in order to gracefully stop the agent.
func NewAgent(ctx context.Context, conf *config.AgentConfig) *Agent {
	dynConf := sampler.NewDynamicConfig()
	in := make(chan *api.Payload, 1000)
	statsChan := make(chan pb.StatsPayload, 100)

	oconf := conf.Obfuscation.Export()
	if oconf.Statsd == nil {
		oconf.Statsd = metrics.Client
	}
	agnt := &Agent{
		Concentrator:          stats.NewConcentrator(conf, statsChan, time.Now()),
		ClientStatsAggregator: stats.NewClientStatsAggregator(conf, statsChan),
		Blacklister:           filters.NewBlacklister(conf.Ignore["resource"]),
		Replacer:              filters.NewReplacer(conf.ReplaceTags),
		PrioritySampler:       sampler.NewPrioritySampler(conf, dynConf),
		ErrorsSampler:         sampler.NewErrorsSampler(conf),
		RareSampler:           sampler.NewRareSampler(),
		NoPrioritySampler:     sampler.NewNoPrioritySampler(conf),
		EventProcessor:        newEventProcessor(conf),
		TraceWriter:           writer.NewTraceWriter(conf),
		StatsWriter:           writer.NewStatsWriter(conf, statsChan),
		obfuscator:            obfuscate.NewObfuscator(oconf),
		cardObfuscator:        newCreditCardsObfuscator(conf.Obfuscation.CreditCards),
		In:                    in,
		conf:                  conf,
		ctx:                   ctx,
	}
	agnt.Receiver = api.NewHTTPReceiver(conf, dynConf, in, agnt)
	agnt.OTLPReceiver = api.NewOTLPReceiver(in, conf.OTLPReceiver)
	return agnt
}

// Run starts routers routines and individual pieces then stop them when the exit order is received
func (a *Agent) Run() {
	for _, starter := range []interface{ Start() }{
		a.Receiver,
		a.Concentrator,
		a.ClientStatsAggregator,
		a.PrioritySampler,
		a.ErrorsSampler,
		a.NoPrioritySampler,
		a.EventProcessor,
		a.OTLPReceiver,
	} {
		starter.Start()
	}

	go a.TraceWriter.Run()
	go a.StatsWriter.Run()

	for i := 0; i < runtime.NumCPU(); i++ {
		go a.work()
	}

	a.loop()
}

// FlushSync flushes traces sychronously. This method only works when the agent is configured in synchronous flushing
// mode via the apm_config.sync_flush option.
func (a *Agent) FlushSync() {
	if !a.conf.SynchronousFlushing {
		log.Critical("(*Agent).FlushSync called without apm_conf.sync_flushing enabled. No data was sent to Datadog.")
		return
	}

	if err := a.StatsWriter.FlushSync(); err != nil {
		log.Errorf("Error flushing stats: %s", err.Error())
		return
	}
	if err := a.TraceWriter.FlushSync(); err != nil {
		log.Errorf("Error flushing traces: %s", err.Error())
		return
	}
}

func (a *Agent) work() {
	for {
		select {
		case p, ok := <-a.In:
			if !ok {
				return
			}
			a.Process(p)
		}
	}

}

func (a *Agent) loop() {
	for {
		select {
		case <-a.ctx.Done():
			log.Info("Exiting...")
			if err := a.Receiver.Stop(); err != nil {
				log.Error(err)
			}
			for _, stopper := range []interface{ Stop() }{
				a.Concentrator,
				a.ClientStatsAggregator,
				a.TraceWriter,
				a.StatsWriter,
				a.PrioritySampler,
				a.ErrorsSampler,
				a.NoPrioritySampler,
				a.RareSampler,
				a.EventProcessor,
				a.OTLPReceiver,
				a.obfuscator,
				a.obfuscator,
				a.cardObfuscator,
			} {
				stopper.Stop()
			}
			return
		}
	}
}

// Process is the default work unit that receives a trace, transforms it and
// passes it downstream.
func (a *Agent) Process(p *api.Payload) {
	if len(p.Chunks()) == 0 {
		log.Debugf("Skipping received empty payload")
		return
	}
	defer timing.Since("datadog.trace_agent.internal.process_payload_ms", time.Now())
	ts := p.Source
	ss := new(writer.SampledChunks)
	a.PrioritySampler.CountClientDroppedP0s(p.ClientDroppedP0s)
	statsInput := stats.NewStatsInput(len(p.TracerPayload.Chunks), p.TracerPayload.ContainerID, p.ClientComputedStats, a.conf)

	p.TracerPayload.Env = traceutil.NormalizeTag(p.TracerPayload.Env)
	for i := 0; i < len(p.Chunks()); {
		chunk := p.Chunk(i)
		if len(chunk.Spans) == 0 {
			log.Debugf("Skipping received empty trace")
			p.RemoveChunk(i)
			continue
		}

		tracen := int64(len(chunk.Spans))
		atomic.AddInt64(&ts.SpansReceived, tracen)
		err := normalizeTrace(p.Source, chunk.Spans)
		if err != nil {
			log.Debugf("Dropping invalid trace: %s", err)
			atomic.AddInt64(&ts.SpansDropped, tracen)
			p.RemoveChunk(i)
			continue
		}

		// Root span is used to carry some trace-level metadata, such as sampling rate and priority.
		root := traceutil.GetRoot(chunk.Spans)
		normalizeChunk(chunk, root)
		if !a.Blacklister.Allows(root) {
			log.Debugf("Trace rejected by ignore resources rules. root: %v", root)
			atomic.AddInt64(&ts.TracesFiltered, 1)
			atomic.AddInt64(&ts.SpansFiltered, tracen)
			p.RemoveChunk(i)
			continue
		}

		if filteredByTags(root, a.conf.RequireTags, a.conf.RejectTags) {
			log.Debugf("Trace rejected as it fails to meet tag requirements. root: %v", root)
			atomic.AddInt64(&ts.TracesFiltered, 1)
			atomic.AddInt64(&ts.SpansFiltered, tracen)
			p.RemoveChunk(i)
			continue
		}

		// Extra sanitization steps of the trace.
		for _, span := range chunk.Spans {
			spanMeta := span.GetMeta()
			a.setGlobalTags(spanMeta, chunk, span)
			if a.ModifySpan != nil {
				a.ModifySpan(span)
			}
			a.obfuscateSpan(span)
			Truncate(span)
			if p.ClientComputedTopLevel {
				traceutil.UpdateTracerTopLevel(span)
			}
		}
		a.Replacer.Replace(chunk.Spans)

		{
			// this section sets up any necessary tags on the root:
			clientSampleRate := sampler.GetGlobalRate(root)
			sampler.SetClientRate(root, clientSampleRate)

			if ratelimiter := a.Receiver.RateLimiter; ratelimiter.Active() {
				rate := ratelimiter.RealRate()
				sampler.SetPreSampleRate(root, rate)
			}
		}
		if !p.ClientComputedTopLevel {
			// Figure out the top-level spans now as it involves modifying the Metrics map
			// which is not thread-safe while samplers and Concentrator might modify it too.
			traceutil.ComputeTopLevel(chunk.Spans)
		}

		if p.TracerPayload.Hostname == "" {
			// Older tracers set tracer hostname in the root span.
			p.TracerPayload.Hostname = root.Meta[tagHostname]
		}
		if p.TracerPayload.Env == "" {
			p.TracerPayload.Env = traceutil.GetEnv(root, chunk)
		}
		if p.TracerPayload.AppVersion == "" {
			p.TracerPayload.AppVersion = traceutil.GetAppVersion(root, chunk)
		}

		pt := traceutil.ProcessedTrace{
			TraceChunk:       chunk,
			Root:             root,
			AppVersion:       p.TracerPayload.AppVersion,
			TracerEnv:        p.TracerPayload.Env,
			TracerHostname:   p.TracerPayload.Hostname,
			ClientDroppedP0s: p.ClientDroppedP0s > 0,
		}
		if !p.ClientComputedStats {
			statsInput.Traces = append(statsInput.Traces, pt)
		}

		numEvents, keep, filteredChunk := a.sample(ts, pt)
		if !keep {
			if numEvents == 0 {
				// the trace was dropped and no analyzed span were kept
				p.RemoveChunk(i)
				continue
			}
			// The sampler step filtered a subset of spans in the chunk. The new filtered chunk
			// is added to the TracerPayload to be sent to TraceWriter.
			// The complete chunk is still sent to the stats concentrator.
			p.ReplaceChunk(i, filteredChunk)
		}

		if !chunk.DroppedTrace {
			ss.SpanCount += int64(len(chunk.Spans))
		}
		ss.EventCount += numEvents
		ss.Size += chunk.Msgsize()
		i++

		if ss.Size > writer.MaxPayloadSize {
			// payload size is getting big; split and flush what we have so far
			ss.TracerPayload = p.TracerPayload.Cut(i)
			i = 0
			a.TraceWriter.In <- ss
			ss = new(writer.SampledChunks)
		}
	}
	ss.TracerPayload = p.TracerPayload
	if ss.Size > 0 {
		a.TraceWriter.In <- ss
	}
	if len(statsInput.Traces) > 0 {
		a.Concentrator.In <- statsInput
	}
}

// setGlobalTags sets the global tags on every span, unless that span is an inferred span with tag_source = self
func (a *Agent) setGlobalTags(spanMeta map[string]string, chunk *pb.TraceChunk, span *pb.Span) {
	if tagSource, ok := spanMeta[inferredSpanTagSourceKey]; !ok || tagSource != inferredSpanTagSourceSelf {
		for k, v := range a.conf.GlobalTags {
			if k == tagOrigin {
				chunk.Origin = v
			} else {
				traceutil.SetMeta(span, k, v)
			}
		}
	}
}

var _ api.StatsProcessor = (*Agent)(nil)

func (a *Agent) processStats(in pb.ClientStatsPayload, lang, tracerVersion string) pb.ClientStatsPayload {
	if features.Has("disable_cid_stats") || a.conf.FargateOrchestrator == fargate.Unknown {
		// this functionality is disabled by the disable_cid_stats feature flag
		// or we're not in a Fargate instance.
		in.ContainerID = ""
		in.Tags = nil
	}
	if in.Env == "" {
		in.Env = a.conf.DefaultEnv
	}
	in.Env = traceutil.NormalizeTag(in.Env)
	in.TracerVersion = tracerVersion
	in.Lang = lang
	for i, group := range in.Stats {
		n := 0
		for _, b := range group.Stats {
			normalizeStatsGroup(&b, lang)
			if !a.Blacklister.AllowsStat(&b) {
				continue
			}
			a.obfuscateStatsGroup(&b)
			a.Replacer.ReplaceStatsGroup(&b)
			group.Stats[n] = b
			n++
		}
		in.Stats[i].Stats = group.Stats[:n]
		mergeDuplicates(in.Stats[i])
	}
	return in
}

func mergeDuplicates(s pb.ClientStatsBucket) {
	indexes := make(map[stats.Aggregation]int, len(s.Stats))
	for i, g := range s.Stats {
		a := stats.NewAggregationFromGroup(g)
		if j, ok := indexes[a]; ok {
			s.Stats[j].Hits += g.Hits
			s.Stats[j].Errors += g.Errors
			s.Stats[j].Duration += g.Duration
			s.Stats[i].Hits = 0
			s.Stats[i].Errors = 0
			s.Stats[i].Duration = 0
		} else {
			indexes[a] = i
		}
	}
}

// ProcessStats processes incoming client stats in from the given tracer.
func (a *Agent) ProcessStats(in pb.ClientStatsPayload, lang, tracerVersion string) {
	a.ClientStatsAggregator.In <- a.processStats(in, lang, tracerVersion)
}

// sample reports the number of events found in pt and whether the chunk should be kept as a trace.
func (a *Agent) sample(ts *info.TagStats, pt traceutil.ProcessedTrace) (numEvents int64, keep bool, filteredChunk *pb.TraceChunk) {
	priority, hasPriority := sampler.GetSamplingPriority(pt.TraceChunk)

	if hasPriority {
		ts.TracesPerSamplingPriority.CountSamplingPriority(priority)
	} else {
		atomic.AddInt64(&ts.TracesPriorityNone, 1)
	}

	if priority < 0 {
		return 0, false, nil
	}

	sampled := a.runSamplers(pt, hasPriority)

	filteredChunk = pt.TraceChunk
	if !sampled {
		filteredChunk = new(pb.TraceChunk)
		*filteredChunk = *pt.TraceChunk
		filteredChunk.DroppedTrace = true
	}
	numEvents, numExtracted := a.EventProcessor.Process(pt.Root, filteredChunk)

	atomic.AddInt64(&ts.EventsExtracted, int64(numExtracted))
	atomic.AddInt64(&ts.EventsSampled, numEvents)

	return numEvents, sampled, filteredChunk
}

// runSamplers runs all the agent's samplers on pt and returns the sampling decision
// along with the sampling rate.
func (a *Agent) runSamplers(pt traceutil.ProcessedTrace, hasPriority bool) bool {
	if hasPriority {
		return a.samplePriorityTrace(pt)
	}
	return a.sampleNoPriorityTrace(pt)
}

// samplePriorityTrace samples traces with priority set on them. PrioritySampler and
// ErrorSampler are run in parallel. The RareSampler catches traces with rare top-level
// or measured spans that are not caught by PrioritySampler and ErrorSampler.
func (a *Agent) samplePriorityTrace(pt traceutil.ProcessedTrace) bool {
	if a.PrioritySampler.Sample(pt.TraceChunk, pt.Root, pt.TracerEnv, pt.ClientDroppedP0s) {
		return true
	}
	if traceContainsError(pt.TraceChunk.Spans) {
		return a.ErrorsSampler.Sample(pt.TraceChunk.Spans, pt.Root, pt.TracerEnv)
	}
	if a.conf.DisableRareSampler {
		return false
	}
	return a.RareSampler.Sample(pt.TraceChunk, pt.TracerEnv)
}

// sampleNoPriorityTrace samples traces with no priority set on them. The traces
// get sampled by either the score sampler or the error sampler if they have an error.
func (a *Agent) sampleNoPriorityTrace(pt traceutil.ProcessedTrace) bool {
	if traceContainsError(pt.TraceChunk.Spans) {
		return a.ErrorsSampler.Sample(pt.TraceChunk.Spans, pt.Root, pt.TracerEnv)
	}
	return a.NoPrioritySampler.Sample(pt.TraceChunk.Spans, pt.Root, pt.TracerEnv)
}

func traceContainsError(trace pb.Trace) bool {
	for _, span := range trace {
		if span.Error != 0 {
			return true
		}
	}
	return false
}

func filteredByTags(root *pb.Span, require, reject []*config.Tag) bool {
	for _, tag := range reject {
		if v, ok := root.Meta[tag.K]; ok && (tag.V == "" || v == tag.V) {
			return true
		}
	}
	for _, tag := range require {
		v, ok := root.Meta[tag.K]
		if !ok || (tag.V != "" && v != tag.V) {
			return true
		}
	}
	return false
}

func newEventProcessor(conf *config.AgentConfig) *event.Processor {
	extractors := []event.Extractor{
		event.NewMetricBasedExtractor(),
	}
	if len(conf.AnalyzedSpansByService) > 0 {
		extractors = append(extractors, event.NewFixedRateExtractor(conf.AnalyzedSpansByService))
	} else if len(conf.AnalyzedRateByServiceLegacy) > 0 {
		extractors = append(extractors, event.NewLegacyExtractor(conf.AnalyzedRateByServiceLegacy))
	}

	return event.NewProcessor(extractors, conf.MaxEPS)
}

// SetGlobalTagsUnsafe sets global tags to the agent configuration. Unsafe for concurrent use.
func (a *Agent) SetGlobalTagsUnsafe(tags map[string]string) {
	a.conf.GlobalTags = tags
}
