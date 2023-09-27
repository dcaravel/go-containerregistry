package registryfaker

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

type timeoutManifestHandler struct {
	Repo string
}

func (h *timeoutManifestHandler) Handle(resp http.ResponseWriter, req *http.Request, repo, target string, _ manifestAccessor, blobHandler BlobHandler) bool {
	if repo != h.Repo {
		return false
	}

	kv := extractKVFromTag(target)

	durStr, ok := kv["dur"]
	if !ok {
		WriteErr(resp, http.StatusBadRequest, "MANIFEST_INVALID", "Tag missing duration")
		return true
	}

	dur, err := time.ParseDuration(durStr)
	if err != nil {
		msg := fmt.Sprintf("error parsing duration: %v", err)
		WriteErr(resp, http.StatusBadRequest, "MANIFEST_INVALID", msg)
		return true
	}

	log.Printf("Sleeping %q for %v", req.URL.Path, dur)
	time.Sleep(dur)

	WriteErr(resp, http.StatusRequestTimeout, "TIMEOUT", "Timeout duration has elapsed!")

	return true
}
