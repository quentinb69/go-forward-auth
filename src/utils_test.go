package main

import (
        "testing"
)

// get user ip
func TestGetIp(t *testing.T) {
        t.Log("TestGetIp")
        //t.Fail()
}

func TestIsValidHash(t *testing.T) {
        t.Log("TestIsValidHash")
        cases := []struct {
                        ClearText string
                        ValidHash string
                        IsValid bool
                } {
                        {"pass", "$2a$10$6.uxYeW/Ucxtom7yjW6Kh..oifG6IPy1ly63AjCArUKmfhu0..wtq", true},
                        {"pwd", "$2a$10$/xN4OWsfJ0P8NCCKYMZa6ugsN9zgfFf9zG94RISv4hZ8eA31qLWX6", true},
                        {"toto", "$2a$10$/xN4OWsfJ0P8NCCKYMZa6ugsN9zgfFf9zG94RISv4hZ8eA31q000", false},
                }
        for _, cas := range cases {
                err := IsValidHash(cas.ClearText, cas.ValidHash)
                if (err == nil) != cas.IsValid {
                        t.Errorf("Error validating hash for %s, got %v, want %v", cas.ClearText, !cas.IsValid, cas.IsValid)
                }
        }
}

func TestGetHash(t *testing.T) {
        t.Log("TestGetHash")
        cases := []string { "toto", "tata", "titi" }
    for _, cas := range cases {
                got, _ := GetHash(cas)
                err := IsValidHash(cas, got)
                if (err != nil) {
                        t.Errorf("Error validating hash for %s, want it to be valid.", cas)
                }
        }
}

// generate random bytes
func TestGenerateRand(t *testing.T) {
        t.Log("TestGenerateRand")
        //t.Fail()
}
