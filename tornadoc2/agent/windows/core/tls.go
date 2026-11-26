//go:build windows

package core

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
)

func ParseECDSAPublicKey(pemBytes []byte) *ecdsa.PublicKey {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil
	}
	return ecdsaPub
}
func parseECDSAPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if priv, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ecdsaPriv, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 key is not ECDSA")
		}
		return ecdsaPriv, nil
	}
	if ecdsaPriv, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return ecdsaPriv, nil
	}
	return nil, errors.New(
		"private key is neither a PKCS#8 nor an SEC1 ECDSA key")
}
func SignPayload(priv *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	hash := sha256.Sum256(payload)
	return ecdsa.SignASN1(crand.Reader, priv, hash[:])
}
func BuildDoHTLSConfig(cfg Config) (*tls.Config, error) {
	out := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
	}
	return out, nil
}
func BuildTLSConfig(cfg Config) (*tls.Config, error) {
	out := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
		ClientSessionCache: tls.NewLRUClientSessionCache(16),
	}

	if p := os.Getenv("SSLKEYLOGFILE"); p != "" {
		if f, err := os.OpenFile(p,
			os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600); err == nil {
			out.KeyLogWriter = f
			diag("[tls] keylog enabled: %s\n", p)
		} else {
			diag("[tls] keylog open failed: %v\n", err)
		}
	}

	_ = cfg

	if cfg.RootCAPem != "" {
		raw, err := base64.StdEncoding.DecodeString(cfg.RootCAPem)
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(raw) {
				out.RootCAs = pool
				out.InsecureSkipVerify = true
				out.VerifyConnection = func(
					cs tls.ConnectionState) error {
					opts := x509.VerifyOptions{
						Roots:         pool,
						Intermediates: x509.NewCertPool(),
					}
					for _, cert := range cs.PeerCertificates[1:] {
						opts.Intermediates.AddCert(cert)
					}
					_, err := cs.PeerCertificates[0].Verify(opts)
					return err
				}
				diag("[tls] RootCA pool loaded — chain " +
					"verification against embedded CA\n")
			} else {
				diag("[tls] RootCAPem could not be added to pool " +
					"— falling back to InsecureSkipVerify\n")
				out.InsecureSkipVerify = true
			}
		} else {
			diag("[tls] RootCAPem b64 decode failed: %v\n", err)
			out.InsecureSkipVerify = true
		}
	} else {
		diag("[tls] no RootCAPem — InsecureSkipVerify enabled\n")
		out.InsecureSkipVerify = true
	}

	if cfg.ClientCertPem != "" && cfg.ClientKeyPem != "" {
		certRaw, err1 := base64.StdEncoding.DecodeString(cfg.ClientCertPem)
		keyRaw, err2 := base64.StdEncoding.DecodeString(cfg.ClientKeyPem)
		if err1 == nil && err2 == nil {
			cert, err := tls.X509KeyPair(certRaw, keyRaw)
			if err != nil {
				return nil, err
			}
			out.Certificates = []tls.Certificate{cert}
			diag("[tls] mTLS client certificate loaded\n")
		} else {
			diag("[tls] mTLS cert or key decode failed "+
				"cert_err=%v key_err=%v\n", err1, err2)
		}
	}

	return out, nil
}
func (a *Agent) buildTLSConfig() (*tls.Config, error) {
	return BuildTLSConfig(a.cfg)
}
