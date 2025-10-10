package sources

import (
	"context"
	"fmt"

	"passive-rec/internal/core/runner"
)

// runSimpleSource es un helper para ejecutar herramientas simples que:
// 1. Verifican si el binario existe
// 2. Emiten mensaje de error si no existe
// 3. Ejecutan el comando con los argumentos dados
func runSimpleSource(ctx context.Context, binNames []string, args []string, out chan<- string, metaName string) error {
	bin, ok := runner.FindBin(binNames...)
	if !ok {
		if out != nil {
			out <- fmt.Sprintf("meta: %s not found in PATH", metaName)
		}
		return runner.ErrMissingBinary
	}
	return runner.RunCommand(ctx, bin, args, out)
}

// runSimpleSingleBin es un helper para herramientas con un solo nombre de binario
func runSimpleSingleBin(ctx context.Context, binName string, args []string, out chan<- string) error {
	if !runner.HasBin(binName) {
		if out != nil {
			out <- fmt.Sprintf("meta: %s not found in PATH", binName)
		}
		return runner.ErrMissingBinary
	}
	return runner.RunCommand(ctx, binName, args, out)
}
