package main

import (
	"testing"
)

// get user ip
func TestGetIp(t *testing.T) {
		t.Log("TestGetIp")
		t.Fail()
}

func TestGetHash(t *testing.T) {
	cases := []struct { Clear, Hash, string} {
        {"pass", "$2y$10$t6XPeRTf5.a.Gb3I/lYq7ukuOpx6fsJRstEXNfOP4jXjjGGZ2Af72"},
		{"pwd", "$2y$10$PpzVO0zStuQKJAHmdIBqQuagxkc732nnGR.Iet4SE5tJR1FjOuo.6"},
    }
	for _, cas := range cases {
		got := GetHash(cas.Clear)
		if got != cas.Hash {
			t.Errorf("GetHash(%s) = %s; want %s", cas.Clear, got, cas.Hash)
		}
	}
}

// compare a hash with a hashed string
func TestIsValidHash(t *testing.T) {
	t.Log("TestIsValidHash")
	t.Fail()
}

// generate random bytes
func TestGenerateRand(t *testing.T) {
	t.Log("TestGenerateRand")
	t.Fail()
}
diff --git a/.github/workflows/tests.yml b/.github/workflows/tests.yml
