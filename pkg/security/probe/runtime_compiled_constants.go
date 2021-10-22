// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build linux

package probe

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode/runtime"
	"github.com/DataDog/datadog-agent/pkg/ebpf/compiler"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

const errorSentinel uint64 = ^uint64(0)

type ConstantFetcher interface {
	AppendSizeofRequest(id, typeName, headerName string)
	AppendOffsetofRequest(id, typeName, fieldName, headerName string)
	FinishAndGetResults() (map[string]uint64, error)
}

type rcSymbolPair struct {
	Id        string
	Operation string
}

type RuntimeCompilationConstantFetcher struct {
	config      *ebpf.Config
	headers     []string
	symbolPairs []rcSymbolPair
	result      map[string]uint64
}

func NewRuntimeCompilationConstantFetcher(config *ebpf.Config) *RuntimeCompilationConstantFetcher {
	return &RuntimeCompilationConstantFetcher{
		config: config,
		result: make(map[string]uint64),
	}
}

func (cf *RuntimeCompilationConstantFetcher) AppendSizeofRequest(id, typeName, headerName string) {
	if headerName != "" {
		cf.headers = append(cf.headers, headerName)
	}

	cf.symbolPairs = append(cf.symbolPairs, rcSymbolPair{
		Id:        id,
		Operation: fmt.Sprintf("sizeof(%s)", typeName),
	})
	cf.result[id] = errorSentinel
}

func (cf *RuntimeCompilationConstantFetcher) AppendOffsetofRequest(id, typeName, fieldName, headerName string) {
	if headerName != "" {
		cf.headers = append(cf.headers, headerName)
	}

	cf.symbolPairs = append(cf.symbolPairs, rcSymbolPair{
		Id:        id,
		Operation: fmt.Sprintf("offsetof(%s, %s)", typeName, fieldName),
	})
	cf.result[id] = errorSentinel
}

const runtimeCompilationTemplate = `
#include <linux/compiler.h>
#include <linux/kconfig.h>
{{ range .headers }}
#include <{{ . }}>
{{ end }}

{{ range .symbols }}
size_t {{.Id}} = {{.Operation}};
{{ end }}
`

func (cf *RuntimeCompilationConstantFetcher) getCCode() (string, error) {
	headers := sortAndDedup(cf.headers)
	tmpl, err := template.New("runtimeCompilationTemplate").Parse(runtimeCompilationTemplate)
	if err != nil {
		return "", err
	}

	var buffer bytes.Buffer
	if err := tmpl.Execute(&buffer, map[string]interface{}{
		"headers": headers,
		"symbols": cf.symbolPairs,
	}); err != nil {
		return "", err
	}

	return buffer.String(), nil
}

func (cf *RuntimeCompilationConstantFetcher) FinishAndGetResults() (map[string]uint64, error) {
	cCode, err := cf.getCCode()
	if err != nil {
		return nil, err
	}

	elfFile, err := compileConstantFetcher(cf.config, cCode)
	if err != nil {
		return nil, err
	}

	f, err := elf.NewFile(elfFile)
	if err != nil {
		return nil, err
	}

	symbols, err := f.Symbols()
	if err != nil {
		return nil, err
	}
	for _, sym := range symbols {
		if _, present := cf.result[sym.Name]; !present {
			continue
		}

		section := f.Sections[sym.Section]
		buf := make([]byte, sym.Size)
		section.ReadAt(buf, int64(sym.Value))

		var value uint64
		switch sym.Size {
		case 4:
			value = uint64(f.ByteOrder.Uint32(buf))
		case 8:
			value = f.ByteOrder.Uint64(buf)
		default:
			return nil, fmt.Errorf("unexpected symbol size: `%v`", sym.Size)
		}

		cf.result[sym.Name] = value
	}

	return cf.result, nil
}

var additionalFlags = []string{
	"-D__KERNEL__",
	"-fno-stack-protector",
	"-fno-color-diagnostics",
	"-fno-unwind-tables",
	"-fno-asynchronous-unwind-tables",
	"-fno-jump-tables",
}

func compileConstantFetcher(config *ebpf.Config, cCode string) (io.ReaderAt, error) {
	dirs, _, err := kernel.GetKernelHeaders(config.KernelHeadersDirs, config.KernelHeadersDownloadDir, config.AptConfigDir, config.YumReposDir, config.ZypperReposDir)
	if err != nil {
		return nil, fmt.Errorf("unable to find kernel headers: %w", err)
	}
	comp, err := compiler.NewEBPFCompiler(dirs, config.BPFDebug)
	if err != nil {
		return nil, fmt.Errorf("failed to create compiler: %w", err)
	}
	defer comp.Close()

	flags, _ := runtime.ComputeFlagsAndHash(additionalFlags)

	outputFile, err := os.CreateTemp("", "datadog_cws_constants_fetcher")
	if err != nil {
		return nil, err
	}

	if err := outputFile.Close(); err != nil {
		return nil, err
	}

	inputReader := strings.NewReader(cCode)
	if err := comp.CompileToObjectFile(inputReader, outputFile.Name(), flags); err != nil {
		return nil, err
	}

	return os.Open(outputFile.Name())
}

func sortAndDedup(in []string) []string {
	// sort and dedup headers
	set := make(map[string]bool)
	for _, value := range in {
		set[value] = true
	}

	out := make([]string, 0, len(in))
	for value, _ := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}