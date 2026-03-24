package service

import (
	"encoding/base64"
	"time"
)

// CursorChecksumKey is the initial XOR key used by the checksum algorithm.
const CursorChecksumKey byte = 165

// GenerateCursorChecksum produces the `x-cursor-checksum` header value.
//
// Algorithm (ported from the reverse-engineered JS implementation):
//  1. Take current timestamp in milliseconds, divide by 1,000,000 (floor).
//  2. Extract 6 bytes from the timestamp (big-endian, bits 40→0).
//  3. XOR-chain each byte with a rolling key, adding the byte index.
//  4. Base64-encode the 6 bytes (standard, no padding via RawStdEncoding).
//  5. Append machineId and optionally /macMachineId.
//
// Reference JS:
//
//	function generateChecksum(machineId, macMachineId) {
//	  let key = 165;
//	  const timestamp = Math.floor(Date.now() / 1e6);
//	  const bytes = new Uint8Array([
//	    (timestamp >> 40) & 255, (timestamp >> 32) & 255,
//	    (timestamp >> 24) & 255, (timestamp >> 16) & 255,
//	    (timestamp >>  8) & 255, timestamp & 255,
//	  ]);
//	  for (let i = 0; i < bytes.length; i++) {
//	    bytes[i] = ((bytes[i] ^ key) + (i % 256)) & 0xFF;
//	    key = bytes[i];
//	  }
//	  const prefix = Buffer.from(bytes).toString('base64');
//	  return macMachineId
//	    ? `${prefix}${machineId}/${macMachineId}`
//	    : `${prefix}${machineId}`;
//	}
func GenerateCursorChecksum(machineId, macMachineId string) string {
	return generateCursorChecksumAt(time.Now(), machineId, macMachineId)
}

// generateCursorChecksumAt is the testable core that accepts an explicit time.
func generateCursorChecksumAt(t time.Time, machineId, macMachineId string) string {
	// JS: Math.floor(Date.now() / 1e6)
	// Date.now() returns milliseconds, so /1e6 keeps the top ~20 bits of ms.
	timestamp := t.UnixMilli() / 1_000_000

	// Extract 6 bytes, big-endian order (bits 40 down to 0).
	raw := [6]byte{
		byte((timestamp >> 40) & 0xFF),
		byte((timestamp >> 32) & 0xFF),
		byte((timestamp >> 24) & 0xFF),
		byte((timestamp >> 16) & 0xFF),
		byte((timestamp >> 8) & 0xFF),
		byte(timestamp & 0xFF),
	}

	// XOR-chain with rolling key.
	key := CursorChecksumKey
	for i := 0; i < 6; i++ {
		raw[i] = byte((int(raw[i]^key) + (i % 256)) & 0xFF)
		key = raw[i]
	}

	// Base64 encode (standard encoding, with padding to match Node's Buffer.toString('base64')).
	prefix := base64.StdEncoding.EncodeToString(raw[:])

	if macMachineId != "" {
		return prefix + machineId + "/" + macMachineId
	}
	return prefix + machineId
}
