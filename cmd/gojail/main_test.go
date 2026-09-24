package main

import (
	"testing"
)

func TestParsePortMappings_Valid(t *testing.T) {
	inputs := []string{"8080:80", "53:53/udp", "3000:3000/tcp"}
	mappings, err := parsePortMappings(inputs)
	if err != nil {
		t.Fatalf("unexpected error parsing valid mappings: %v", err)
	}

	if len(mappings) != 3 {
		t.Fatalf("expected 3 mappings, got %d", len(mappings))
	}

	if mappings[0].HostPort != 8080 || mappings[0].ContainerPort != 80 || mappings[0].Protocol != "tcp" {
		t.Errorf("unexpected mapping[0]: %+v", mappings[0])
	}
	if mappings[1].HostPort != 53 || mappings[1].ContainerPort != 53 || mappings[1].Protocol != "udp" {
		t.Errorf("unexpected mapping[1]: %+v", mappings[1])
	}
	if mappings[2].HostPort != 3000 || mappings[2].ContainerPort != 3000 || mappings[2].Protocol != "tcp" {
		t.Errorf("unexpected mapping[2]: %+v", mappings[2])
	}
}

func TestParsePortMappings_Invalid(t *testing.T) {
	testCases := []struct {
		name  string
		input []string
	}{
		{"invalid format", []string{"8080"}},
		{"negative host port", []string{"-1:80"}},
		{"port out of bounds", []string{"70000:80"}},
		{"invalid protocol", []string{"8080:80/sctp"}},
		{"non-numeric port", []string{"http:80"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePortMappings(tc.input)
			if err == nil {
				t.Fatalf("expected error for input %v, got nil", tc.input)
			}
		})
	}
}
