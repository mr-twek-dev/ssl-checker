package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
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
	Host       string
	Port       string
	CheckedAt  time.Time
	Protocol   string
	Cipher     string
	PeerName   string
	Leaf       CertificateInfo
	Chain      []CertificateInfo
	Revocation RevocationCheck
	Verified   bool
	Problems   []string
}

type RevocationCheck struct {
	Checked        bool
	Revoked        bool
	Source         string
	Reason         string
	RevocationTime time.Time
	Message        string
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
	revocation := checkCertificateRevocation(ctx, state.PeerCertificates)
	problems := certificateWarnings(host, state.PeerCertificates, revocation)

	return &TLSCheckResult{
		Host:       host,
		Port:       port,
		CheckedAt:  time.Now().UTC(),
		Protocol:   tlsVersionName(state.Version),
		Cipher:     tls.CipherSuiteName(state.CipherSuite),
		PeerName:   conn.RemoteAddr().String(),
		Leaf:       leaf,
		Chain:      chain,
		Revocation: revocation,
		Verified:   true,
		Problems:   problems,
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
		fmt.Sprintf("Отзыв: %s", formatRevocationStatus(result.Revocation)),
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

func certificateWarnings(host string, certs []*x509.Certificate, revocation RevocationCheck) []string {
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
	if revocation.Revoked {
		problems = append(problems, "Сертификат отозван: "+revocation.Message)
	}
	if len(certs) <= 1 {
		problems = append(problems, "Сервер вернул только leaf-сертификат; промежуточные сертификаты не получены.")
	}
	return problems
}

func checkCertificateRevocation(ctx context.Context, certs []*x509.Certificate) RevocationCheck {
	leaf := certs[0]
	if len(leaf.CRLDistributionPoints) == 0 {
		return RevocationCheck{Message: "CRL Distribution Points отсутствуют"}
	}
	var issuer *x509.Certificate
	if len(certs) > 1 {
		issuer = certs[1]
	}
	var lastMessage string
	for _, crlURL := range leaf.CRLDistributionPoints {
		check, err := checkCRL(ctx, leaf.SerialNumber, issuer, crlURL)
		if err != nil {
			lastMessage = err.Error()
			continue
		}
		return check
	}
	if lastMessage == "" {
		lastMessage = "не удалось проверить CRL"
	}
	return RevocationCheck{Source: strings.Join(leaf.CRLDistributionPoints, ", "), Message: lastMessage}
}

func checkCRL(ctx context.Context, serial *big.Int, issuer *x509.Certificate, crlURL string) (RevocationCheck, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, nil)
	if err != nil {
		return RevocationCheck{}, err
	}
	client := http.Client{Timeout: defaultTimeout}
	response, err := client.Do(request)
	if err != nil {
		return RevocationCheck{}, fmt.Errorf("CRL %s недоступен: %w", crlURL, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return RevocationCheck{}, fmt.Errorf("CRL %s вернул HTTP %s", crlURL, response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 10*1024*1024))
	if err != nil {
		return RevocationCheck{}, err
	}
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return RevocationCheck{}, fmt.Errorf("CRL %s не удалось разобрать: %w", crlURL, err)
	}
	if issuer != nil {
		if err := crl.CheckSignatureFrom(issuer); err != nil {
			return RevocationCheck{}, fmt.Errorf("подпись CRL %s недействительна: %w", crlURL, err)
		}
	}
	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(serial) == 0 {
			return RevocationCheck{
				Checked:        true,
				Revoked:        true,
				Source:         crlURL,
				Reason:         revocationReason(revoked.ReasonCode),
				RevocationTime: revoked.RevocationTime.UTC(),
				Message:        fmt.Sprintf("найден в CRL %s, время отзыва %s, причина: %s", crlURL, revoked.RevocationTime.UTC().Format("2006-01-02 15:04:05 UTC"), revocationReason(revoked.ReasonCode)),
			}, nil
		}
	}
	return RevocationCheck{Checked: true, Source: crlURL, Message: "сертификат не найден в CRL"}, nil
}

func revocationReason(code int) string {
	switch code {
	case 0:
		return "unspecified"
	case 1:
		return "keyCompromise"
	case 2:
		return "cACompromise"
	case 3:
		return "affiliationChanged"
	case 4:
		return "superseded"
	case 5:
		return "cessationOfOperation"
	case 6:
		return "certificateHold"
	case 8:
		return "removeFromCRL"
	case 9:
		return "privilegeWithdrawn"
	case 10:
		return "aACompromise"
	default:
		return fmt.Sprintf("unknown(%d)", code)
	}
}

func formatRevocationStatus(check RevocationCheck) string {
	if check.Revoked {
		return "ОТОЗВАН — " + check.Message
	}
	if check.Checked {
		return "не отозван по CRL " + check.Source
	}
	return "не проверен — " + check.Message
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
