package sources

import (
	"context"
)

func Subfinder(ctx context.Context, target string, out chan<- string) error {
	return runSimpleSingleBin(ctx, "subfinder", []string{"-d", target, "-silent"}, out)
}
