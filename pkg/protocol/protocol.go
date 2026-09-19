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

// StreamType distinguishes between different frame payloads.
type StreamType uint8

const (
	StreamStdout StreamType = 1
	StreamStderr StreamType = 2
	StreamExit   StreamType = 3
	StreamStdin  StreamType = 4
	StreamResize StreamType = 5
)

// WindowSize conveys terminal dimensions across the wire.
type WindowSize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

// ExitPayload serializes the final termination details.
type ExitPayload struct {
	ExitCode int                     `json:"exit_code"`
	Duration time.Duration           `json:"duration"`
	TimedOut bool                    `json:"timed_out"`
	Metrics  sandbox.ResourceMetrics `json:"metrics"`
	Error    string                  `json:"error,omitempty"`
}

// FrameWriter encodes binary frames onto an io.Writer.
type FrameWriter struct {
	w io.Writer
}

// NewFrameWriter constructs a FrameWriter.
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w}
}

// WriteFrame sends a single binary-encoded frame: [Type: 1B][Length: 4B (BigEndian)][Payload]
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

// WriteExitFrame encodes an ExitPayload as a StreamExit frame.
func (fw *FrameWriter) WriteExitFrame(payload ExitPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal exit payload: %w", err)
	}
	return fw.WriteFrame(StreamExit, data)
}

// FrameReader decodes binary frames from an io.Reader.
type FrameReader struct {
	r io.Reader
}

// NewFrameReader constructs a FrameReader.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r}
}

// ReadFrame reads the next binary frame from the underlying reader.
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

// ParseExitPayload deserializes a StreamExit frame payload.
func ParseExitPayload(payload []byte) (*ExitPayload, error) {
	var exitPayload ExitPayload
	if err := json.Unmarshal(payload, &exitPayload); err != nil {
		return nil, err
	}
	return &exitPayload, nil
}

// ParseWindowSize deserializes a StreamResize frame payload.
func ParseWindowSize(payload []byte) (*WindowSize, error) {
	if len(payload) < 4 {
		return nil, errors.New("invalid resize payload length")
	}
	return &WindowSize{
		Rows: binary.BigEndian.Uint16(payload[0:2]),
		Cols: binary.BigEndian.Uint16(payload[2:4]),
	}, nil
}

// EncodeWindowSize serializes terminal rows and cols into 4 bytes.
func EncodeWindowSize(rows, cols uint16) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], rows)
	binary.BigEndian.PutUint16(buf[2:4], cols)
	return buf
}
