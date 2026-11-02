package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

func toUtlsCertificates(in []tls.Certificate) []utls.Certificate {
	if len(in) == 0 {
		return nil
	}
	out := make([]utls.Certificate, len(in))
	for i, c := range in {
		out[i] = utls.Certificate{
			Certificate:                  c.Certificate,
			PrivateKey:                   c.PrivateKey,
			SupportedSignatureAlgorithms: toUtlsSigSchemes(c.SupportedSignatureAlgorithms),
			OCSPStaple:                   c.OCSPStaple,
			SignedCertificateTimestamps:  c.SignedCertificateTimestamps,
			Leaf:                         c.Leaf,
		}
	}
	return out
}

func toUtlsSigSchemes(in []tls.SignatureScheme) []utls.SignatureScheme {
	if len(in) == 0 {
		return nil
	}
	out := make([]utls.SignatureScheme, len(in))
	for i, s := range in {
		out[i] = utls.SignatureScheme(s)
	}
	return out
}

func utlsDialTLS(cfg *tls.Config, profile string) func(
	ctx context.Context, network, addr string,
) (net.Conn, error) {
	helloID := pickClientHelloID(profile)

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		raw, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			host = addr
		}
		serverName := host
		if isIPLiteral(host) {
			serverName = ""
		}

		uCfg := &utls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			RootCAs:            cfg.RootCAs,
			Certificates:       toUtlsCertificates(cfg.Certificates),
			MinVersion:         cfg.MinVersion,
			MaxVersion:         cfg.MaxVersion,
			NextProtos: []string{"http/1.1"},
		}

		conn := utls.UClient(raw, uCfg, helloID)
		if err := conn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}

		if cfg.RootCAs != nil {
			state := conn.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				conn.Close()
				return nil, fmt.Errorf(
					"utls: server presented no certificate")
			}
			opts := x509.VerifyOptions{
				Roots:         cfg.RootCAs,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range state.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			if _, err := state.PeerCertificates[0].Verify(opts); err != nil {
				conn.Close()
				return nil, fmt.Errorf("utls: chain verify failed: %w", err)
			}
		}
		return conn, nil
	}
}

func pickClientHelloID(profile string) utls.ClientHelloID {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "firefox":
		return utls.HelloFirefox_120
	case "safari":
		return utls.HelloSafari_16_0
	case "chrome", "":
		return utls.HelloChrome_120
	default:
		return utls.HelloChrome_120
	}
}

func isIPLiteral(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return net.ParseIP(s[1:len(s)-1]) != nil
	}
	return false
}