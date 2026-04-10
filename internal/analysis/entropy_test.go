package analysis

import (
	"math"
	"testing"
	"time"
)

func TestShannonEntropy_AllZeros(t *testing.T) {
	// All same bytes → entropy = 0.
	data := make([]byte, 1024)
	e := ShannonEntropy(data)
	if e != 0.0 {
		t.Errorf("entropy of all zeros = %f, want 0.0", e)
	}
}

func TestShannonEntropy_AllDifferent(t *testing.T) {
	// 256 unique bytes each appearing once → maximum entropy = 8.0.
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	e := ShannonEntropy(data)
	if math.Abs(e-8.0) > 0.001 {
		t.Errorf("entropy of 256 unique bytes = %f, want ~8.0", e)
	}
}

func TestShannonEntropy_TwoValues(t *testing.T) {
	// Equal distribution of 2 values → entropy = 1.0.
	data := make([]byte, 1000)
	for i := range data {
		if i%2 == 0 {
			data[i] = 0
		} else {
			data[i] = 1
		}
	}
	e := ShannonEntropy(data)
	if math.Abs(e-1.0) > 0.01 {
		t.Errorf("entropy of 50/50 two values = %f, want ~1.0", e)
	}
}

func TestShannonEntropy_Empty(t *testing.T) {
	e := ShannonEntropy([]byte{})
	if e != 0.0 {
		t.Errorf("entropy of empty = %f, want 0.0", e)
	}
}

func TestDetectTimestampAnomaly_Zeroed(t *testing.T) {
	result := detectTimestampAnomaly(0)
	if result != "zeroed" {
		t.Errorf("anomaly = %q, want zeroed", result)
	}
}

func TestDetectTimestampAnomaly_Epoch(t *testing.T) {
	// Very low timestamp (within first day of epoch).
	result := detectTimestampAnomaly(100)
	if result != "epoch" {
		t.Errorf("anomaly = %q, want epoch", result)
	}
}

func TestDetectTimestampAnomaly_Pre1990(t *testing.T) {
	// 1985-01-01 00:00:00 UTC.
	ts := uint32(time.Date(1985, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	result := detectTimestampAnomaly(ts)
	if result != "pre-1990" {
		t.Errorf("anomaly = %q, want pre-1990", result)
	}
}

func TestDetectTimestampAnomaly_Future(t *testing.T) {
	// 2 years from now.
	future := time.Now().UTC().Add(2 * 365 * 24 * time.Hour)
	ts := uint32(future.Unix())
	result := detectTimestampAnomaly(ts)
	if result != "future" {
		t.Errorf("anomaly = %q, want future", result)
	}
}

func TestDetectTimestampAnomaly_Normal(t *testing.T) {
	// 2023-06-15 — well within normal range.
	ts := uint32(time.Date(2023, 6, 15, 12, 0, 0, 0, time.UTC).Unix())
	result := detectTimestampAnomaly(ts)
	if result != "" {
		t.Errorf("anomaly = %q, want empty (normal)", result)
	}
}
