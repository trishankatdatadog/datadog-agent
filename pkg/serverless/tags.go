// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package serverless

import (
	"fmt"
	"os"
	"strings"
)

const (
	qualifierEnvVar = "AWS_LAMBDA_FUNCTION_VERSION"

	traceOriginMetadataKey   = "_dd.origin"
	traceOriginMetadataValue = "lambda"
	computeStatsKey          = "_dd.compute_stats"
	computeStatsValue        = "1"
	functionARNKey           = "function_arn"
	functionNameKey          = "functionname"
	regionKey                = "region"
	awsAccountKey            = "aws_account"
	resourceKey              = "resource"
	executedVersionKey       = "executedversion"
)

func buildTagMapFromArn(arn string) map[string]string {
	tags := make(map[string]string)

	tags = setIfNotEmpty(tags, traceOriginMetadataKey, traceOriginMetadataValue)
	tags = setIfNotEmpty(tags, computeStatsKey, computeStatsValue)
	tags = setIfNotEmpty(tags, functionARNKey, arn)

	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return tags
	}

	tags = setIfNotEmpty(tags, regionKey, parts[3])
	tags = setIfNotEmpty(tags, awsAccountKey, parts[4])
	tags = setIfNotEmpty(tags, functionNameKey, parts[6])
	tags = setIfNotEmpty(tags, resourceKey, parts[6])

	qualifier := os.Getenv(qualifierEnvVar)
	if len(qualifier) > 0 {
		if qualifier != "$LATEST" {
			tags = setIfNotEmpty(tags, resourceKey, fmt.Sprintf("%s:%s", parts[6], qualifier))
			tags = setIfNotEmpty(tags, executedVersionKey, qualifier)
		}
	}

	return tags
}

func buildTagsFromMap(configTags []string, tags map[string]string, tagBlackList []string) []string {
	tagsMap := make(map[string]string)
	for k, v := range tags {
		tagsMap[k] = v
	}
	for _, blackListKey := range tagBlackList {
		delete(tagsMap, blackListKey)
	}
	tagsArray := make([]string, 0, len(configTags)+len(tagsMap))
	tagsArray = append(tagsArray, configTags...)
	for key, value := range tagsMap {
		tagsArray = append(tagsArray, fmt.Sprintf("%s:%s", key, value))
	}
	return tagsArray
}

func buildTracerTags(tags map[string]string, tagBlackList []string) map[string]string {
	tagsMap := make(map[string]string)
	for k, v := range tags {
		tagsMap[k] = v
	}
	for _, blackListKey := range tagBlackList {
		delete(tagsMap, blackListKey)
	}
	return tagsMap
}

func setIfNotEmpty(tagMap map[string]string, key string, value string) map[string]string {
	if key != "" {
		tagMap[key] = strings.ToLower(value)
	}
	return tagMap
}

func blackListTagForMetricsAndLogs() []string {
	return []string{traceOriginMetadataKey, computeStatsKey}
}

func blackListTagForTraces() []string {
	return []string{resourceKey}
}
