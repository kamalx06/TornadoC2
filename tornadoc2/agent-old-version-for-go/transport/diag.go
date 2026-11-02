package transport

import (
	"fmt"
	"os"
)

var Verbose bool

func diag(format string, args ...interface{}) {
	if !Verbose {
		return
	}
	fmt.Fprintf(os.Stderr, format, args...)
}