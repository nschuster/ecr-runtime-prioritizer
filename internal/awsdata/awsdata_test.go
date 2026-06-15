package awsdata

import (
	"context"
	"testing"
)

func TestNewLeavesProfileEmptyForDefaultCredentialChain(t *testing.T) {
	s, err := New(context.Background(), "")
	if err != nil {
		t.Fatalf("New with empty profile should load the default AWS credential chain: %v", err)
	}
	if s.profile != "" {
		t.Fatalf("expected empty profile, got %q", s.profile)
	}
}
