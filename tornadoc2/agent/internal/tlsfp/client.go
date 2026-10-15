package tlsfp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

func HelloIDForProfile(profile string) (utls.ClientHelloID, bool, error) {
	switch profile {
	case "", "go":
		return utls.ClientHelloID{}, false, nil
	case "chrome":
		return utls.HelloChrome_120, true, nil
	case "firefox":
		return utls.HelloFirefox_120, true, nil
	case "safari":
		return utls.HelloSafari_16_0, true, nil
	}
	return utls.ClientHelloID{}, false, fmt.Errorf(
		"unknown tls_profile %q; valid values are go, "+
			"chrome, firefox, safari", profile)
}

func NewHTTPClient(profile string,
	tlsCfg *tls.Config) (*http.Client, error) {
	tr, err := newTransport(profile, tlsCfg, false)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: tr,
	}, nil
}

func NewDoHClient(profile string,
	tlsCfg *tls.Config) (*http.Client, error) {
	tr, err := newTransport(profile, tlsCfg, false)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request,
			via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// ---------------------------------------------------------------------

var warnOnce sync.Once

func newTransport(profile string, cfg *tls.Config,
	forceH2Off bool) (*http.Transport, error) {

	hello, useUTLS, err := HelloIDForProfile(profile)
	if err != nil {
		return nil, err
	}

	if !useUTLS {
		return &http.Transport{
			TLSClientConfig:       cfg,
			ForceAttemptHTTP2:     !forceH2Off,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		}, nil
	}

	utlsCfg, missing := translateConfig(cfg)
	if len(missing) > 0 {
		warnOnce.Do(func() {
			for _, f := range missing {
				fmt.Printf("[tlsfp] warning: tls.Config.%s has "+
					"no uTLS equivalent; the field is not "+
					"applied under profile %q\n", f, profile)
			}
		})
	}

	return &http.Transport{
		DialTLSContext: func(ctx context.Context,
			network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 15 * time.Second}
			raw, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			uconn := utls.UClient(raw, utlsCfg, hello)
			if err := uconn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return uconn, nil
		},
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}, nil
}

func translateConfig(cfg *tls.Config) (*utls.Config, []string) {
	var missing []string
	out := &utls.Config{}

	out.InsecureSkipVerify = cfg.InsecureSkipVerify
	out.RootCAs = cfg.RootCAs
	out.ServerName = cfg.ServerName
	out.MinVersion = cfg.MinVersion
	out.MaxVersion = cfg.MaxVersion
	out.CipherSuites = cfg.CipherSuites
	out.NextProtos = cfg.NextProtos

	if len(cfg.Certificates) > 0 {
		converted := make([]utls.Certificate, 0, len(cfg.Certificates))
		for _, c := range cfg.Certificates {
			converted = append(converted, utls.Certificate{
				Certificate: c.Certificate,
				PrivateKey:  c.PrivateKey,
				Leaf:        c.Leaf,
			})
		}
		out.Certificates = converted
	}

	if cfg.ClientSessionCache != nil {
		out.ClientSessionCache = utls.NewLRUClientSessionCache(16)
	}

	if cfg.VerifyConnection != nil {
		fn := cfg.VerifyConnection
		out.VerifyConnection = func(cs utls.ConnectionState) error {
			return fn(convertUTLSConnState(cs))
		}
	}

	if cfg.GetClientCertificate != nil {
		missing = append(missing, "GetClientCertificate")
	}
	if cfg.VerifyPeerCertificate != nil {
		missing = append(missing, "VerifyPeerCertificate")
	}
	if cfg.KeyLogWriter != nil {
		missing = append(missing, "KeyLogWriter")
	}
	if len(cfg.CurvePreferences) > 0 {
		missing = append(missing, "CurvePreferences")
	}
	if cfg.Renegotiation != tls.RenegotiateNever {
		missing = append(missing, "Renegotiation")
	}
	if cfg.SessionTicketsDisabled {
		missing = append(missing, "SessionTicketsDisabled")
	}
	if cfg.DynamicRecordSizingDisabled {
		missing = append(missing, "DynamicRecordSizingDisabled")
	}
	if len(cfg.EncryptedClientHelloConfigList) > 0 {
		missing = append(missing, "EncryptedClientHelloConfigList")
	}
	if cfg.Rand != nil {
		missing = append(missing, "Rand")
	}
	if cfg.Time != nil {
		missing = append(missing, "Time")
	}

	return out, missing
}

func convertUTLSConnState(cs utls.ConnectionState) tls.ConnectionState {
	out := tls.ConnectionState{
		Version:                     cs.Version,
		HandshakeComplete:           cs.HandshakeComplete,
		DidResume:                   cs.DidResume,
		CipherSuite:                 cs.CipherSuite,
		NegotiatedProtocol:          cs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
		ServerName:                  cs.ServerName,
		PeerCertificates:            cs.PeerCertificates,
		VerifiedChains:              cs.VerifiedChains,
		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
		OCSPResponse:                cs.OCSPResponse,
		TLSUnique:                   cs.TLSUnique,
	}
	return out
}