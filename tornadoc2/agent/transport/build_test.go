package transport

import "testing"

func TestBuildUnknown(t *testing.T) {
	if _, err := Build("nope", Options{}); err == nil {
		t.Fatal("expected unknown transport error")
	}
}

func TestBuiltReports(t *testing.T) {
	// t.HTTP is not guaranteed in every tag set; this only checks
	// that the registry answers consistently with Build.
	for _, name := range []string{"http", "does-not-exist"} {
		built := Built(name)
		_, err := Build(name, Options{})
		if built && err != nil {
			// registration exists; failure is a parameter error
			continue
		}
		if !built && err == nil {
			t.Fatalf("%s: unregistered but Build succeeded", name)
		}
	}
}
