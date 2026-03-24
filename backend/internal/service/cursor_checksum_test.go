package service

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// ============================================================
// Checksum Tests
// ============================================================

func TestGenerateCursorChecksum_Format(t *testing.T) {
	machineId := "aaaabbbbccccddddeeeeffffgggghhhh"
	macMachineId := "11112222333344445555666677778888"

	result := GenerateCursorChecksum(machineId, macMachineId)

	// The result must contain machineId and macMachineId separated by /
	if !strings.Contains(result, machineId+"/"+macMachineId) {
		t.Errorf("checksum should contain machineId/macMachineId, got: %s", result)
	}

	// The prefix (base64 of 6 bytes) is at least 8 chars (6 bytes → 8 base64 chars with padding)
	prefix := strings.TrimSuffix(result, machineId+"/"+macMachineId)
	if len(prefix) < 8 {
		t.Errorf("prefix too short: %q (len=%d)", prefix, len(prefix))
	}
}

func TestGenerateCursorChecksum_WithoutMacMachineId(t *testing.T) {
	machineId := "aaaabbbbccccddddeeeeffffgggghhhh"

	result := GenerateCursorChecksum(machineId, "")

	// Should NOT contain a slash
	if strings.Contains(result, "/") {
		t.Errorf("checksum without macMachineId should not contain /, got: %s", result)
	}

	if !strings.HasSuffix(result, machineId) {
		t.Errorf("checksum should end with machineId, got: %s", result)
	}
}

func TestGenerateCursorChecksum_Deterministic(t *testing.T) {
	machineId := "test-machine-id-1234567890abcdef"
	macMachineId := "mac-machine-id-fedcba0987654321"
	fixedTime := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	result1 := generateCursorChecksumAt(fixedTime, machineId, macMachineId)
	result2 := generateCursorChecksumAt(fixedTime, machineId, macMachineId)

	if result1 != result2 {
		t.Errorf("same time should produce same checksum:\n  %s\n  %s", result1, result2)
	}
}

func TestGenerateCursorChecksum_DifferentTimes(t *testing.T) {
	machineId := "test-machine-id"
	macMachineId := "test-mac-id"

	// Two times far enough apart (>1e6 ms = ~16.7 minutes) to differ
	t1 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)

	r1 := generateCursorChecksumAt(t1, machineId, macMachineId)
	r2 := generateCursorChecksumAt(t2, machineId, macMachineId)

	if r1 == r2 {
		t.Error("different times should produce different checksums")
	}
}

// Validate deterministic output at a known timestamp.
// The expected prefix is verified by running the Go algorithm directly.
func TestGenerateCursorChecksum_ReferenceVector(t *testing.T) {
	fixedTime := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	machineId := "mid"
	macMachineId := "mmid"

	result := generateCursorChecksumAt(fixedTime, machineId, macMachineId)

	// Verify it ends with the correct suffix
	expectedSuffix := "mid/mmid"
	if !strings.HasSuffix(result, expectedSuffix) {
		t.Errorf("expected suffix %q, got: %s", expectedSuffix, result)
	}

	// Verified prefix from running the algorithm: "paaotTnc"
	expectedPrefix := "paaotTnc"
	prefix := strings.TrimSuffix(result, expectedSuffix)
	if prefix != expectedPrefix {
		t.Errorf("expected prefix %q, got %q\nfull result: %s", expectedPrefix, prefix, result)
	}

	// Verify the full result matches
	expectedFull := "paaotTncmid/mmid"
	if result != expectedFull {
		t.Errorf("expected full checksum %q, got %q", expectedFull, result)
	}
}

// ============================================================
// Protocol (Envelope Frame) Tests
// ============================================================

func TestCursorFrameEncodeJSON(t *testing.T) {
	type msg struct {
		Hello string `json:"hello"`
	}

	frame, err := CursorFrameEncodeJSON(msg{Hello: "world"})
	if err != nil {
		t.Fatal(err)
	}

	// Header check
	if frame[0] != CursorFrameFlagData {
		t.Errorf("flag should be 0x00, got 0x%02x", frame[0])
	}

	// Length check
	jsonBytes, _ := json.Marshal(msg{Hello: "world"})
	expectedLen := len(jsonBytes)
	if got := int(frame[1])<<24 | int(frame[2])<<16 | int(frame[3])<<8 | int(frame[4]); got != expectedLen {
		t.Errorf("length: expected %d, got %d", expectedLen, got)
	}

	// Data check
	if string(frame[5:]) != string(jsonBytes) {
		t.Errorf("data mismatch: %s vs %s", frame[5:], jsonBytes)
	}
}

func TestCursorFrameDecodeAll_SingleFrame(t *testing.T) {
	original := map[string]string{"key": "value"}
	frame, err := CursorFrameEncodeJSON(original)
	if err != nil {
		t.Fatal(err)
	}

	frames, remaining := CursorFrameDecodeAll(frame)
	if len(remaining) != 0 {
		t.Errorf("expected no remaining, got %d bytes", len(remaining))
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}

	var decoded map[string]string
	if err := CursorFrameDecodeJSON(frames[0], &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["key"] != "value" {
		t.Errorf("expected 'value', got '%s'", decoded["key"])
	}
}

func TestCursorFrameDecodeAll_MultipleFrames(t *testing.T) {
	frame1, _ := CursorFrameEncodeJSON(map[string]int{"a": 1})
	frame2, _ := CursorFrameEncodeJSON(map[string]int{"b": 2})
	frame3, _ := CursorFrameEncodeJSON(map[string]int{"c": 3})

	combined := make([]byte, 0, len(frame1)+len(frame2)+len(frame3))
	combined = append(combined, frame1...)
	combined = append(combined, frame2...)
	combined = append(combined, frame3...)

	frames, remaining := CursorFrameDecodeAll(combined)
	if len(remaining) != 0 {
		t.Errorf("expected no remaining, got %d bytes", len(remaining))
	}
	if len(frames) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(frames))
	}
}

func TestCursorFrameDecodeAll_IncompleteFrame(t *testing.T) {
	frame, _ := CursorFrameEncodeJSON(map[string]string{"test": "data"})

	// Truncate to simulate incomplete read
	partial := frame[:len(frame)-3]
	frames, remaining := CursorFrameDecodeAll(partial)

	if len(frames) != 0 {
		t.Errorf("expected 0 frames from incomplete data, got %d", len(frames))
	}
	if len(remaining) != len(partial) {
		t.Errorf("all bytes should remain, expected %d got %d", len(partial), len(remaining))
	}
}

func TestCursorFrameDecodeAll_CompleteAndIncomplete(t *testing.T) {
	frame1, _ := CursorFrameEncodeJSON(map[string]int{"x": 1})
	frame2, _ := CursorFrameEncodeJSON(map[string]int{"y": 2})

	// Complete frame1 + incomplete frame2
	combined := make([]byte, 0, len(frame1)+len(frame2))
	combined = append(combined, frame1...)
	combined = append(combined, frame2[:len(frame2)-2]...) // Truncate frame2

	frames, remaining := CursorFrameDecodeAll(combined)
	if len(frames) != 1 {
		t.Fatalf("expected 1 complete frame, got %d", len(frames))
	}
	if len(remaining) == 0 {
		t.Error("expected remaining bytes from incomplete frame2")
	}
}

func TestCursorFrameReader(t *testing.T) {
	// Build a multi-frame buffer
	frame1, _ := CursorFrameEncodeJSON(map[string]string{"msg": "hello"})
	frame2, _ := CursorFrameEncodeJSON(map[string]string{"msg": "world"})

	buf := make([]byte, 0, len(frame1)+len(frame2))
	buf = append(buf, frame1...)
	buf = append(buf, frame2...)

	reader := NewCursorFrameReader(bytes.NewReader(buf))

	// Read first frame
	f1, err := reader.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	var m1 map[string]string
	if err := CursorFrameDecodeJSON(*f1, &m1); err != nil {
		t.Fatal(err)
	}
	if m1["msg"] != "hello" {
		t.Errorf("expected 'hello', got '%s'", m1["msg"])
	}

	// Read second frame
	f2, err := reader.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	var m2 map[string]string
	if err := CursorFrameDecodeJSON(*f2, &m2); err != nil {
		t.Fatal(err)
	}
	if m2["msg"] != "world" {
		t.Errorf("expected 'world', got '%s'", m2["msg"])
	}

	// EOF
	_, err = reader.ReadFrame()
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestCursorFrameWriter(t *testing.T) {
	var buf bytes.Buffer
	writer := NewCursorFrameWriter(&buf)

	err := writer.WriteJSON(map[string]string{"test": "value"})
	if err != nil {
		t.Fatal(err)
	}

	frames, remaining := CursorFrameDecodeAll(buf.Bytes())
	if len(remaining) != 0 {
		t.Errorf("expected no remaining, got %d bytes", len(remaining))
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}

	var decoded map[string]string
	if err := CursorFrameDecodeJSON(frames[0], &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["test"] != "value" {
		t.Errorf("expected 'value', got '%s'", decoded["test"])
	}
}

func TestCursorFrameEncodeRaw(t *testing.T) {
	data := []byte(`{"raw":"data"}`)
	frame := CursorFrameEncodeRaw(data)

	frames, _ := CursorFrameDecodeAll(frame)
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if string(frames[0].Data) != string(data) {
		t.Errorf("data mismatch: %s vs %s", frames[0].Data, data)
	}
}

func TestCursorFrameDecodeAll_EmptyInput(t *testing.T) {
	frames, remaining := CursorFrameDecodeAll(nil)
	if len(frames) != 0 {
		t.Errorf("expected 0 frames, got %d", len(frames))
	}
	if len(remaining) != 0 {
		t.Errorf("expected 0 remaining, got %d", len(remaining))
	}

	frames, remaining = CursorFrameDecodeAll([]byte{})
	if len(frames) != 0 {
		t.Errorf("expected 0 frames for empty slice, got %d", len(frames))
	}
}

func TestCursorFrameDecodeAll_HeaderOnly(t *testing.T) {
	// 5 bytes header but claims 100 bytes of data → incomplete
	buf := []byte{0x00, 0x00, 0x00, 0x00, 100}
	frames, remaining := CursorFrameDecodeAll(buf)
	if len(frames) != 0 {
		t.Errorf("expected 0 frames, got %d", len(frames))
	}
	if len(remaining) != 5 {
		t.Errorf("expected 5 remaining, got %d", len(remaining))
	}
}
