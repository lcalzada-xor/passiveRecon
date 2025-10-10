package sources

import (
	"context"

	"passive-rec/internal/adapters/sources/linkfinderevo"
)

// LinkFinderEVO ejecuta el binario GoLinkfinderEVO sobre HTML/JS/crawl activos,
// agrega resultados, persiste artefactos y emite rutas clasificadas al sink.
func LinkFinderEVO(ctx context.Context, target string, outdir string, out chan<- string) error {
	return linkfinderevo.Run(ctx, target, outdir, out)
}
