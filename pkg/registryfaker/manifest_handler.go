package registryfaker

import "net/http"

type manifestHandler interface {
	// Handle returns true if it handled the request
	Handle(resp http.ResponseWriter, req *http.Request, repo, target string, mAccessor manifestAccessor, blobHandler BlobHandler) bool
}

type manifestAccessor interface {
	PutManifest(repo, digest, tag string, manifest manifest)
	GetManifest(repo, digest string) (manifest, *regError)
}
