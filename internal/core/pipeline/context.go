package pipeline

type Context struct {
	S     *Sink
	Store ArtifactStore
	Dedup *Dedupe
}
