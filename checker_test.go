package main

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeTargetAcceptsURLHostAndPort(t *testing.T) {
	tests := []struct {
		input string
		host  string
		port  string
	}{
		{input: "https://example.com/path", host: "example.com", port: "443"},
		{input: "example.com:8443", host: "example.com", port: "8443"},
	}
	for _, test := range tests {
		host, port, err := NormalizeTarget(test.input)
		if err != nil {
			t.Fatalf("NormalizeTarget(%q) returned error: %v", test.input, err)
		}
		if host != test.host || port != test.port {
			t.Fatalf("NormalizeTarget(%q) = %s:%s, want %s:%s", test.input, host, port, test.host, test.port)
		}
	}
}

func TestNormalizeTargetRejectsEmptyValue(t *testing.T) {
	if _, _, err := NormalizeTarget("   "); err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestFormatResultContainsCertificateAndChainInformation(t *testing.T) {
	now := time.Now().UTC()
	cert := CertificateInfo{
		Subject:            "CN=example.com",
		Issuer:             "CN=Example CA",
		SerialNumber:       "1",
		NotBefore:          now.Add(-time.Hour),
		NotAfter:           now.Add(30 * 24 * time.Hour),
		DNSNames:           []string{"example.com"},
		SignatureAlgorithm: "SHA256-RSA",
		PublicKeyAlgorithm: "RSA",
		Version:            3,
		SHA256Fingerprint:  "aa:bb",
	}
	result := &TLSCheckResult{
		Host:      "example.com",
		Port:      "443",
		CheckedAt: now,
		Protocol:  "TLS 1.3",
		Cipher:    "TLS_AES_256_GCM_SHA384",
		PeerName:  "93.184.216.34:443",
		Leaf:      cert,
		Chain:     []CertificateInfo{cert},
		Verified:  true,
	}

	text := FormatResult(result)
	for _, expected := range []string{"TLS проверка: example.com:443", "Сертификат сайта", "Цепочка сертификатов: 1", "SHA-256: aa:bb"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("formatted result does not contain %q:\n%s", expected, text)
		}
	}
}
