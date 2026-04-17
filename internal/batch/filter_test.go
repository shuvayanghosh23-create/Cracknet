package batch

import (
	"reflect"
	"sort"
	"testing"
)

func makeGroups() map[string][]HashEntry {
	return map[string][]HashEntry{
		"md5":    {{Hash: "aaa", Algorithm: "md5"}, {Hash: "bbb", Algorithm: "md5"}},
		"sha1":   {{Hash: "ccc", Algorithm: "sha1"}},
		"bcrypt": {{Hash: "$2b$12$xxx", Algorithm: "bcrypt"}},
	}
}

func TestFilterGroups_NoFilter(t *testing.T) {
	groups := makeGroups()
	got, warns := FilterGroups(groups, "", "")
	if len(warns) != 0 {
		t.Errorf("expected no warnings, got %v", warns)
	}
	if len(got) != len(groups) {
		t.Errorf("expected %d groups, got %d", len(groups), len(got))
	}
}

func TestFilterGroups_Only(t *testing.T) {
	groups := makeGroups()
	got, warns := FilterGroups(groups, "md5,sha1", "")
	if len(warns) != 0 {
		t.Errorf("expected no warnings, got %v", warns)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 groups, got %d", len(got))
	}
	if _, ok := got["md5"]; !ok {
		t.Error("expected md5 in result")
	}
	if _, ok := got["sha1"]; !ok {
		t.Error("expected sha1 in result")
	}
	if _, ok := got["bcrypt"]; ok {
		t.Error("bcrypt should be excluded")
	}
}

func TestFilterGroups_Skip(t *testing.T) {
	groups := makeGroups()
	got, warns := FilterGroups(groups, "", "bcrypt")
	if len(warns) != 0 {
		t.Errorf("expected no warnings, got %v", warns)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 groups, got %d", len(got))
	}
	if _, ok := got["bcrypt"]; ok {
		t.Error("bcrypt should be skipped")
	}
}

func TestFilterGroups_OnlyMissing(t *testing.T) {
	groups := makeGroups()
	got, warns := FilterGroups(groups, "md5,sha512", "")
	if len(warns) != 1 || warns[0] != "sha512" {
		t.Errorf("expected warning for sha512, got %v", warns)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 group, got %d", len(got))
	}
	if _, ok := got["md5"]; !ok {
		t.Error("expected md5 in result")
	}
}

func TestFilterGroups_SkipAll(t *testing.T) {
	groups := makeGroups()
	got, warns := FilterGroups(groups, "", "md5,sha1,bcrypt")
	if len(warns) != 0 {
		t.Errorf("expected no warnings, got %v", warns)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 groups, got %d", len(got))
	}
}

func TestSplitAlgoList(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"md5,sha1", []string{"md5", "sha1"}},
		{"MD5, SHA1 , bcrypt", []string{"md5", "sha1", "bcrypt"}},
		{"", nil},
		{",,,", nil},
		{"bcrypt", []string{"bcrypt"}},
	}
	for _, tc := range tests {
		got := SplitAlgoList(tc.input)
		sort.Strings(got)
		want := tc.want
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("SplitAlgoList(%q) = %v, want %v", tc.input, got, want)
		}
	}
}
