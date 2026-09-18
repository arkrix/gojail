package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/arkrix/gojail/pkg/sandbox"
)

// StreamType identifies the channel of a stream frame.
type StreamType byte

const (
	StreamStdout StreamType = 1
	StreamStderr StreamType = 2
	StreamExit   StreamType = 3
)

// ExitPayload carries the final execution metadata in the StreamExit frame.
type ExitPayload struct {
	ExitCode int                     `json:"exit_code"`
	Duration time.Duration           `json:"duration"`
	TimedOut bool                    `json:"timed_out"`
	Metrics  sandbox.ResourceMetrics `json:"metrics"`
	Error    string                  `json:"error,omitempty"`
}

// FrameWriter encodes data frames into an underlying writer.
type FrameWriter struct {
	w io.Writer
}

// NewFrameWriter initializes a frame encoder.
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w}
}

// WriteFrame sends a single framed packet over the wire.
func (fw *FrameWriter) WriteFrame(streamType StreamType, payload []byte) error {
	header := make([]byte, 5)
	header[0] = byte(streamType)
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))

	if _, err := fw.w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := fw.w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// WriteExitFrame serializes and sends the final ExitPayload frame.
func (fw *FrameWriter) WriteExitFrame(payload ExitPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal exit payload: %w", err)
	}
	return fw.WriteFrame(StreamExit, data)
}

// FrameReader decodes streaming frames from an underlying reader.
type FrameReader struct {
	r io.Reader
}

// NewFrameReader initializes a frame decoder.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r}
}

// ReadFrame reads the next single frame from the stream.
func (fr *FrameReader) ReadFrame() (StreamType, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(fr.r, header); err != nil {
		return 0, nil, err
	}

	streamType := StreamType(header[0])
	length := binary.BigEndian.Uint32(header[1:])

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(fr.r, payload); err != nil {
			return 0, nil, err
		}
	}

	return streamType, payload, nil
}

// ParseExitPayload decodes the exit payload body from a StreamExit frame.
func ParseExitPayload(payload []byte) (*ExitPayload, error) {
	if len(payload) == 0 {
		return nil, errors.New("empty exit payload")
	}
	var exit ExitPayload
	if err := json.Unmarshal(payload, &exit); err != nil {
		return nil, fmt.Errorf("failed to decode exit payload: %w", err)
	}
	return &exit, nil
}
