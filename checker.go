package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPort    = "443"
	defaultTimeout = 10 * time.Second
)

type CertificateInfo struct {
	Subject            string
	Issuer             string
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	DNSNames           []string
	IPAddresses        []string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	Version            int
	SHA256Fingerprint  string
	IsCA               bool
}

type TLSCheckResult struct {
	Host      string
	Port      string
	CheckedAt time.Time
	Protocol  string
	Cipher    string
	PeerName  string
	Leaf      CertificateInfo
	Chain     []CertificateInfo
	Verified  bool
	Problems  []string
}

func NormalizeTarget(rawTarget string) (string, string, error) {
	target := strings.TrimSpace(rawTarget)
	if target == "" {
		return "", "", fmt.Errorf("укажите URL или hostname")
	}
	if !strings.Contains(target, "://") {
		target = "//" + target
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return "", "", fmt.Errorf("не удалось разобрать адрес: %w", err)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("не удалось определить hostname из введенного значения")
	}
	port := parsed.Port()
	if port == "" {
		port = defaultPort
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", fmt.Errorf("порт должен быть в диапазоне 1-65535")
	}
	return host, port, nil
}

func CheckTLSCertificate(ctx context.Context, rawTarget string) (*TLSCheckResult, error) {
	host, port, err := NormalizeTarget(rawTarget)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	dialer := tls.Dialer{Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("TLS подключение не удалось: %w", err)
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("сервер не вернул сертификат")
	}

	chain := make([]CertificateInfo, 0, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		chain = append(chain, certificateInfo(cert))
	}
	leaf := chain[0]
	problems := certificateWarnings(host, state.PeerCertificates)

	return &TLSCheckResult{
		Host:      host,
		Port:      port,
		CheckedAt: time.Now().UTC(),
		Protocol:  tlsVersionName(state.Version),
		Cipher:    tls.CipherSuiteName(state.CipherSuite),
		PeerName:  conn.RemoteAddr().String(),
		Leaf:      leaf,
		Chain:     chain,
		Verified:  true,
		Problems:  problems,
	}, nil
}

func FormatResult(result *TLSCheckResult) string {
	leaf := result.Leaf
	lines := []string{
		fmt.Sprintf("🔐 TLS проверка: %s:%s", result.Host, result.Port),
		fmt.Sprintf("Время проверки: %s", result.CheckedAt.Format("2006-01-02 15:04:05 UTC")),
		fmt.Sprintf("Сервер: %s", result.PeerName),
		fmt.Sprintf("Протокол: %s", result.Protocol),
		fmt.Sprintf("Шифр: %s", result.Cipher),
		"",
		"📄 Сертификат сайта",
		fmt.Sprintf("Subject: %s", leaf.Subject),
		fmt.Sprintf("Issuer: %s", leaf.Issuer),
		fmt.Sprintf("Serial: %s", leaf.SerialNumber),
		fmt.Sprintf("Действителен с: %s", leaf.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC")),
		fmt.Sprintf("Действителен до: %s", leaf.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC")),
		fmt.Sprintf("Осталось дней: %d", daysLeft(leaf.NotAfter)),
		fmt.Sprintf("SAN DNS: %s", joinOrNone(leaf.DNSNames)),
		fmt.Sprintf("SAN IP: %s", joinOrNone(leaf.IPAddresses)),
		fmt.Sprintf("Подпись: %s", leaf.SignatureAlgorithm),
		fmt.Sprintf("Публичный ключ: %s", leaf.PublicKeyAlgorithm),
		fmt.Sprintf("SHA-256: %s", leaf.SHA256Fingerprint),
		"",
		fmt.Sprintf("🔗 Цепочка сертификатов: %d", len(result.Chain)),
	}
	for index, cert := range result.Chain {
		role := "issuer"
		if index == 0 {
			role = "leaf"
		}
		lines = append(lines,
			fmt.Sprintf("%d. %s: %s", index+1, role, cert.Subject),
			fmt.Sprintf("   Issuer: %s", cert.Issuer),
			fmt.Sprintf("   До: %s (%d дн.)", cert.NotAfter.UTC().Format("2006-01-02"), daysLeft(cert.NotAfter)),
		)
	}
	if len(result.Problems) > 0 {
		lines = append(lines, "", "⚠️ Предупреждения:")
		for _, problem := range result.Problems {
			lines = append(lines, "- "+problem)
		}
	} else {
		lines = append(lines, "", "✅ Сертификат и доверенная цепочка успешно проверены.")
	}
	return strings.Join(lines, "\n")
}

func certificateInfo(cert *x509.Certificate) CertificateInfo {
	fingerprint := sha256.Sum256(cert.Raw)
	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.Text(16),
		NotBefore:          cert.NotBefore.UTC(),
		NotAfter:           cert.NotAfter.UTC(),
		DNSNames:           append([]string(nil), cert.DNSNames...),
		IPAddresses:        ips,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		Version:            cert.Version,
		SHA256Fingerprint:  colonHex(fingerprint[:]),
		IsCA:               cert.IsCA,
	}
}

func certificateWarnings(host string, certs []*x509.Certificate) []string {
	var problems []string
	leaf := certs[0]
	now := time.Now().UTC()
	if now.After(leaf.NotAfter) {
		problems = append(problems, "Сертификат уже истек.")
	} else if daysLeft(leaf.NotAfter) <= 14 {
		problems = append(problems, fmt.Sprintf("Сертификат истекает скоро: осталось %d дн.", daysLeft(leaf.NotAfter)))
	}
	if now.Before(leaf.NotBefore) {
		problems = append(problems, "Сертификат еще не начал действовать.")
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		problems = append(problems, "В сертификате нет Subject Alternative Name.")
	} else if err := leaf.VerifyHostname(host); err != nil {
		problems = append(problems, "Hostname не найден в SAN сертификата.")
	}
	if len(certs) <= 1 {
		problems = append(problems, "Сервер вернул только leaf-сертификат; промежуточные сертификаты не получены.")
	}
	return problems
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("unknown (%d)", version)
	}
}

func daysLeft(deadline time.Time) int {
	return int(time.Until(deadline).Hours() / 24)
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "нет"
	}
	return strings.Join(values, ", ")
}

func colonHex(bytes []byte) string {
	encoded := hex.EncodeToString(bytes)
	parts := make([]string, 0, len(encoded)/2)
	for i := 0; i < len(encoded); i += 2 {
		parts = append(parts, encoded[i:i+2])
	}
	return strings.Join(parts, ":")
}
