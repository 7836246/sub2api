package service

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// ConnectRPC Envelope frame constants
const (
	// CursorFrameFlagData indicates an uncompressed data frame.
	CursorFrameFlagData byte = 0x00
	// CursorFrameFlagCompressed indicates a compressed frame.
	CursorFrameFlagCompressed byte = 0x02
	// CursorFrameHeaderLen is the fixed 5-byte header: 1 byte flag + 4 bytes big-endian length.
	CursorFrameHeaderLen = 5
)

// CursorFrame represents a single ConnectRPC envelope frame.
type CursorFrame struct {
	Flag byte
	Data []byte
}

// CursorFrameEncodeJSON encodes a Go value as JSON, wraps it in a ConnectRPC
// envelope frame, and returns the raw bytes.
//
// Wire format:
//
//	┌──────┬──────────────┬────────────────┐
//	│ Flag │   Length     │    Data        │
//	│ 1B   │   4B (BE)   │  N bytes       │
//	└──────┴──────────────┴────────────────┘
func CursorFrameEncodeJSON(v any) ([]byte, error) {
	jsonBuf, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("cursor frame encode: marshal json: %w", err)
	}

	frame := make([]byte, CursorFrameHeaderLen+len(jsonBuf))
	frame[0] = CursorFrameFlagData
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(jsonBuf)))
	copy(frame[5:], jsonBuf)
	return frame, nil
}

// CursorFrameEncodeRaw wraps raw bytes (already encoded) in an envelope frame.
func CursorFrameEncodeRaw(data []byte) []byte {
	frame := make([]byte, CursorFrameHeaderLen+len(data))
	frame[0] = CursorFrameFlagData
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(data)))
	copy(frame[5:], data)
	return frame
}

// CursorFrameDecodeAll reads all complete frames from buffer. Returns parsed
// frames and any remaining bytes that form an incomplete trailing frame.
func CursorFrameDecodeAll(buf []byte) (frames []CursorFrame, remaining []byte) {
	offset := 0
	for offset+CursorFrameHeaderLen <= len(buf) {
		flag := buf[offset]
		dataLen := binary.BigEndian.Uint32(buf[offset+1 : offset+5])
		offset += CursorFrameHeaderLen

		if offset+int(dataLen) > len(buf) {
			// Incomplete frame — rewind
			offset -= CursorFrameHeaderLen
			break
		}

		data := make([]byte, dataLen)
		copy(data, buf[offset:offset+int(dataLen)])

		frames = append(frames, CursorFrame{
			Flag: flag,
			Data: data,
		})
		offset += int(dataLen)
	}

	if offset < len(buf) {
		remaining = buf[offset:]
	}
	return
}

// CursorFrameDecodeJSON decodes a single frame's Data field as JSON into dst.
func CursorFrameDecodeJSON(frame CursorFrame, dst any) error {
	return json.Unmarshal(frame.Data, dst)
}

// CursorFrameReader wraps an io.Reader and yields frames one at a time.
type CursorFrameReader struct {
	r   io.Reader
	buf bytes.Buffer
}

// NewCursorFrameReader creates a frame reader over the given io.Reader.
func NewCursorFrameReader(r io.Reader) *CursorFrameReader {
	return &CursorFrameReader{r: r}
}

// ReadFrame reads the next complete frame. It blocks until a full frame is
// available or the underlying reader returns an error.
func (fr *CursorFrameReader) ReadFrame() (*CursorFrame, error) {
	// Read header
	for fr.buf.Len() < CursorFrameHeaderLen {
		if err := fr.fill(); err != nil {
			return nil, err
		}
	}

	// Peek at header to find data length
	header := fr.buf.Bytes()[:CursorFrameHeaderLen]
	flag := header[0]
	dataLen := binary.BigEndian.Uint32(header[1:5])
	totalLen := CursorFrameHeaderLen + int(dataLen)

	// Read until we have the full frame
	for fr.buf.Len() < totalLen {
		if err := fr.fill(); err != nil {
			return nil, err
		}
	}

	// Extract the frame
	frameBuf := make([]byte, totalLen)
	_, _ = fr.buf.Read(frameBuf)

	data := make([]byte, dataLen)
	copy(data, frameBuf[CursorFrameHeaderLen:])

	return &CursorFrame{
		Flag: flag,
		Data: data,
	}, nil
}

// fill reads more data from the underlying reader into the buffer.
func (fr *CursorFrameReader) fill() error {
	tmp := make([]byte, 4096)
	n, err := fr.r.Read(tmp)
	if n > 0 {
		fr.buf.Write(tmp[:n])
	}
	if err != nil {
		return err
	}
	return nil
}

// CursorFrameWriter wraps an io.Writer and writes envelope frames.
type CursorFrameWriter struct {
	w io.Writer
}

// NewCursorFrameWriter creates a frame writer over the given io.Writer.
func NewCursorFrameWriter(w io.Writer) *CursorFrameWriter {
	return &CursorFrameWriter{w: w}
}

// WriteJSON marshals v to JSON and writes it as an envelope frame.
func (fw *CursorFrameWriter) WriteJSON(v any) error {
	frame, err := CursorFrameEncodeJSON(v)
	if err != nil {
		return err
	}
	_, err = fw.w.Write(frame)
	return err
}

// WriteRaw writes raw bytes as an envelope frame.
func (fw *CursorFrameWriter) WriteRaw(data []byte) error {
	frame := CursorFrameEncodeRaw(data)
	_, err := fw.w.Write(frame)
	return err
}
