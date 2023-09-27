package registryfaker

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type preparedManifestHandler struct {
	Repo string
}

func (h *preparedManifestHandler) Handle(resp http.ResponseWriter, req *http.Request, repo, target string, mAccessor manifestAccessor, blobHandler BlobHandler) bool {
	fmt.Println("In preparedManifestHandler")
	if repo != h.Repo {
		return false
	}

	// Check storage for manifest
	mf, err := mAccessor.GetManifest(repo, target)
	if err != nil {
		if isDigest(target) {
			err.Write(resp)
			return true
		}
	}

	hash, _, _ := v1.SHA256(bytes.NewReader(mf.blob))
	resp.Header().Set("Docker-Content-Digest", hash.String())
	resp.Header().Set("Content-Type", mf.contentType)
	resp.Header().Set("Content-Length", fmt.Sprint(len(mf.blob)))
	resp.WriteHeader(http.StatusOK)
	io.Copy(resp, bytes.NewReader(mf.blob))
	return true
}
