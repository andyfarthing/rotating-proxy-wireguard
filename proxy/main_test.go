package main

import (
	"os"
	"testing"
	"time"
)

func TestMustDuration(t *testing.T) {
	tests := []struct {
		name     string
		envValue string // empty = unset (uses fallback)
		fallback string
		want     time.Duration
		wantPanic bool
	}{
		// Bare numbers → treated as seconds
		{name: "bare integer env", envValue: "30", fallback: "5", want: 30 * time.Second},
		{name: "bare integer fallback", envValue: "", fallback: "5", want: 5 * time.Second},
		{name: "bare integer 1", envValue: "1", fallback: "5", want: 1 * time.Second},

		// Explicit Go duration strings → still work
		{name: "go duration seconds", envValue: "30s", fallback: "5", want: 30 * time.Second},
		{name: "go duration milliseconds", envValue: "500ms", fallback: "5", want: 500 * time.Millisecond},
		{name: "go duration minutes", envValue: "2m", fallback: "5", want: 2 * time.Minute},

		// Invalid value → panic
		{name: "invalid value", envValue: "notaduration", fallback: "5", wantPanic: true},
	}

	const testKey = "TEST_DURATION_VAR"

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envValue != "" {
				os.Setenv(testKey, tc.envValue)
				defer os.Unsetenv(testKey)
			} else {
				os.Unsetenv(testKey)
			}

			if tc.wantPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("expected panic for value %q but did not panic", tc.envValue)
					}
				}()
			}

			got := mustDuration(testKey, tc.fallback)

			if !tc.wantPanic && got != tc.want {
				t.Errorf("mustDuration(%q, %q) = %v, want %v", tc.envValue, tc.fallback, got, tc.want)
			}
		})
	}
}
