// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package decoder

import (
	"bytes"
	"regexp"
	"time"

	"github.com/DataDog/datadog-agent/pkg/logs/config"
)

// MultiLineHandler makes sure that multiple lines from a same content
// are properly put together.
type MultiLineHandler struct {
	inputChan      chan *Message
	outputChan     chan *Message
	newContentRe   *regexp.Regexp
	buffer         *bytes.Buffer
	flushTimeout   time.Duration
	lineLimit      int
	shouldTruncate bool
	linesLen       int
	status         string
	timestamp      string
	countInfo      *config.CountInfo
}

// NewMultiLineHandler returns a new MultiLineHandler.
func NewMultiLineHandler(inputChan chan *Message, outputChan chan *Message, newContentRe *regexp.Regexp, flushTimeout time.Duration, lineLimit int) *MultiLineHandler {
	return &MultiLineHandler{
		inputChan:    inputChan,
		outputChan:   outputChan,
		newContentRe: newContentRe,
		buffer:       bytes.NewBuffer(nil),
		flushTimeout: flushTimeout,
		lineLimit:    lineLimit,
		countInfo:    config.NewCountInfo("MultiLine matches"),
	}
}

// Start starts the handler.
func (h *MultiLineHandler) Start() {
	go h.run()
}

// run processes new lines from the channel and makes sur the content is properly sent when
// it stayed for too long in the buffer.
func (h *MultiLineHandler) run() {
	flushTimer := time.NewTimer(h.flushTimeout)
	defer func() {
		flushTimer.Stop()
		// make sure the content stored in the buffer gets sent,
		// this can happen when the stop is called in between two timer ticks.
		h.sendBuffer()
		close(h.outputChan)
	}()
	for {
		select {
		case message, isOpen := <-h.inputChan:
			if !isOpen {
				// lineChan has been closed, no more lines are expected
				return
			}
			// process the new line and restart the timeout
			if !flushTimer.Stop() {
				// timer stop doesn't not prevent the timer to tick,
				// makes sure the event is consumed to avoid sending
				// just one piece of the content.
				select {
				case <-flushTimer.C:
				default:
				}
			}
			h.process(message)
			flushTimer.Reset(h.flushTimeout)
		case <-flushTimer.C:
			// no line has been collected since a while,
			// the content is supposed to be complete.
			h.sendBuffer()
		}
	}
}

// process aggregates multiple lines to form a full multiline message,
// it stops when a line matches with the new content regular expression.
// It also makes sure that the content will never exceed the limit
// and that the length of the lines is properly tracked
// so that the agent restarts tailing from the right place.
func (h *MultiLineHandler) process(message *Message) {

	if h.newContentRe.Match(message.Content) {
		h.countInfo.Add(1)
		// the current line is part of a new message,
		// send the buffer
		h.sendBuffer()
	}

	isTruncated := h.shouldTruncate
	h.shouldTruncate = false

	// track the raw data length and the timestamp so that the agent tails
	// from the right place at restart
	h.linesLen += message.RawDataLen
	h.timestamp = message.Timestamp
	h.status = message.Status

	if h.buffer.Len() > 0 {
		// the buffer already contains some data which means that
		// the current line is not the first line of the message
		h.buffer.Write(escapedLineFeed)
	}

	if isTruncated {
		// the previous line has been truncated because it was too long,
		// the new line is just a remainder,
		// adding the truncated flag at the beginning of the content
		h.buffer.Write(truncatedFlag)
	}

	h.buffer.Write(message.Content)

	if h.buffer.Len() >= h.lineLimit {
		// the multiline message is too long, it needs to be cut off and send,
		// adding the truncated flag the end of the content
		h.buffer.Write(truncatedFlag)
		h.sendBuffer()
		h.shouldTruncate = true
	}
}

// sendBuffer forwards the content stored in the buffer
// to the output channel.
func (h *MultiLineHandler) sendBuffer() {
	defer func() {
		h.buffer.Reset()
		h.linesLen = 0
		h.shouldTruncate = false
	}()

	data := bytes.TrimSpace(h.buffer.Bytes())
	content := make([]byte, len(data))
	copy(content, data)

	if len(content) > 0 || h.linesLen > 0 {
		h.outputChan <- NewMessage(content, h.status, h.linesLen, h.timestamp)
	}
}
