package main

import (
        "testing"
	"net/http"
)

// get user ip
func TestGetIp(t *testing.T) {
        t.Log("TestGetIp")
	req, _ := http.NewRequest("POST", "http://localhost", nil)

	expectedIp := "3.3.3.3"
	ip := GetIp(req)
	req.RemoteAddr = expectedIp+":123456"
	if ip != expectedIp {
		t.Errorf("Error validating IP, want %v, got %v", expectedIp, ip)
	}
	expectedIp = "2.2.2.2"
	req.Header.Set("X-Forwarded-For", expectedIp+":123456, 9.9.9.9, 8.7.6.8:1235")
	ip = GetIp(req)
	if ip != expectedIp {
		t.Errorf("Error validating IP, want %v, got %v", expectedIp, ip)
	}

	expectedIp="3.3.3.3"
	req.Header.Add("X-Real-IP", expectedIp)
t.Errorf("%v", req)
	ip = GetIp(req)
	if ip != expectedIp {
		t.Errorf("Error validating IP, want %v, got %v", expectedIp, ip)
	}
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

func TestGenerateRand(t *testing.T) {
        t.Log("TestGenerateRand")
	cases := []uint { 5, 10, 99, 0 }
	for _, cas := range cases {
		n, err := GenerateRand(cas)
		if cas < 0 && err == nil {
			t.Errorf("Error Generating random, want error for %v", cas)
		} else if len(*n) != int(cas) {
			t.Errorf("Error Generating random, want %v, got %v", cas, len(*n))
		}
	}

}
