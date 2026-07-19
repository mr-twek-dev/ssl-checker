package main

import (
	"crypto/x509"
	"os"
	"path/filepath"
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

func TestSaveAndLoadWatcherConfigs(t *testing.T) {
	bot := NewTelegramBot("token")
	bot.watchersFile = t.TempDir() + "/watchers.json"
	bot.watchers[watcherKey(42, "example.com")] = watcherEntry{
		Config: WatchConfig{ChatID: 42, Target: "example.com", IntervalSeconds: 300},
		Cancel: func() {},
	}

	if err := bot.saveWatchers(); err != nil {
		t.Fatalf("saveWatchers returned error: %v", err)
	}

	loaded, err := bot.loadWatcherConfigs()
	if err != nil {
		t.Fatalf("loadWatcherConfigs returned error: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d configs, want 1", len(loaded))
	}
	if loaded[0].ChatID != 42 || loaded[0].Target != "example.com" || loaded[0].IntervalSeconds != 300 {
		t.Fatalf("unexpected watcher config: %+v", loaded[0])
	}
}

func TestFormatInterval(t *testing.T) {
	if got := formatInterval(2 * time.Hour); got != "2 ч" {
		t.Fatalf("formatInterval(2h) = %q", got)
	}
	if got := formatInterval(15 * time.Minute); got != "15 мин" {
		t.Fatalf("formatInterval(15m) = %q", got)
	}
}

func TestCertificateWarningsIncludesRevokedCertificate(t *testing.T) {
	now := time.Now().UTC()
	cert := &x509.Certificate{
		DNSNames:  []string{"example.com"},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(30 * 24 * time.Hour),
	}
	problems := certificateWarnings("example.com", []*x509.Certificate{cert, cert}, RevocationCheck{
		Revoked: true,
		Message: "найден в CRL",
	})
	found := false
	for _, problem := range problems {
		if strings.Contains(problem, "Сертификат отозван") {
			found = true
		}
	}
	if !found {
		t.Fatalf("revoked certificate warning not found in %+v", problems)
	}
}

func TestFormatRevocationStatus(t *testing.T) {
	if got := formatRevocationStatus(RevocationCheck{Checked: true, Source: "http://crl.example/ca.crl"}); !strings.Contains(got, "не отозван") {
		t.Fatalf("expected non-revoked status, got %q", got)
	}
	if got := formatRevocationStatus(RevocationCheck{Revoked: true, Message: "найден в CRL"}); !strings.Contains(got, "ОТОЗВАН") {
		t.Fatalf("expected revoked status, got %q", got)
	}
}

func TestDefaultWatchersPathUsesEnvironmentOverride(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WATCHERS_FILE", "/tmp/custom-watchers.json")
	if got := defaultWatchersPath(); got != "/tmp/custom-watchers.json" {
		t.Fatalf("defaultWatchersPath() = %q", got)
	}
}

func TestDefaultWatchersPathDoesNotUseProjectDataDirectory(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("WATCHERS_FILE", "")
	got := defaultWatchersPath()
	if strings.Contains(got, ".data/watchers.json") {
		t.Fatalf("defaultWatchersPath() uses project-local .data path: %q", got)
	}
	if !strings.HasSuffix(got, "ssl-checker/watchers.json") {
		t.Fatalf("defaultWatchersPath() = %q, want ssl-checker/watchers.json suffix", got)
	}
}

func TestDefaultWatchersPathFallsBackWhenEnvironmentPathIsNotWritable(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())
	blockingFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockingFile, []byte("block"), 0o600); err != nil {
		t.Fatalf("failed to create blocking file: %v", err)
	}
	badPath := filepath.Join(blockingFile, "watchers.json")
	t.Setenv("WATCHERS_FILE", badPath)

	bot := NewTelegramBot("token")
	if bot.watchersFile == badPath {
		t.Fatalf("watchersFile did not move away from unwritable WATCHERS_FILE")
	}
	bot.watchers[watcherKey(42, "example.com")] = watcherEntry{
		Config: WatchConfig{ChatID: 42, Target: "example.com", IntervalSeconds: 300},
		Cancel: func() {},
	}

	if err := bot.saveWatchers(); err != nil {
		t.Fatalf("saveWatchers returned error after fallback path resolution: %v", err)
	}
	if _, err := os.Stat(bot.watchersFile); err != nil {
		t.Fatalf("watchers file was not written: %v", err)
	}
}
