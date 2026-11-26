package transport

import "net/http"

// applyBrowserDefaults fills the headers a real browser sends and
// a profile has not overridden. Go's defaults (Accept-Encoding
// only, no Accept/Accept-Language) are a cheap fingerprint; these
// values are the normal Chrome/Firefox baseline.
func applyBrowserDefaults(req *http.Request) {
	setDefault(req, "Accept",
		"text/html,application/xhtml+xml,application/xml;q=0.9,"+
			"image/avif,image/webp,*/*;q=0.8")
	setDefault(req, "Accept-Language", "en-US,en;q=0.9")
	setDefault(req, "Cache-Control", "no-cache")
	setDefault(req, "Pragma", "no-cache")
}

func setDefault(req *http.Request, key, value string) {
	if req.Header.Get(key) == "" {
		req.Header.Set(key, value)
	}
}
