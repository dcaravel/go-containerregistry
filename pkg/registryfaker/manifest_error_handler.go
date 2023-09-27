package registryfaker

import "net/http"

type errorManifestHandler struct {
	Repo string
}

func (h *errorManifestHandler) Handle(resp http.ResponseWriter, req *http.Request, repo, target string, _ manifestAccessor, blobHandler BlobHandler) bool {
	if repo != h.Repo {
		return false
	}

	switch target {
	case "400":
		WriteErr(resp, http.StatusBadRequest, "MANIFEST_INVALID", "Eww! That request looks bad, very bad... just awful.")
	case "403":
		WriteErr(resp, http.StatusForbidden, "FORBIDDEN", "Fakereg: Access to this resource is forbidden")
	case "404":
		WriteErr(resp, http.StatusNotFound, "MANIFEST_UNKNOWN", "Looking for something?")
	case "405":
		WriteErr(resp, http.StatusMethodNotAllowed, "UNAUTHORIZED", "Method not allowed")
	case "500":
		WriteErr(resp, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Working as intended... probably...")
	default:
		WriteErr(resp, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Huh?")
	}

	return true
}
