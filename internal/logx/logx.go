package logx

import (
	"fmt"
	"os"
	"time"
)

var verbosity = 0

func SetVerbosity(v int) { verbosity = v }

// V(level>=1 info, >=2 debug)
func V(level int, format string, a ...interface{}) {
	if verbosity >= level {
		prefix := "[INFO]"
		if level >= 2 {
			prefix = "[DEBUG]"
		}
		fmt.Fprintf(os.Stderr, "%s %s %s\n",
			time.Now().Format(time.RFC3339),
			prefix,
			fmt.Sprintf(format, a...),
		)
	}
}
