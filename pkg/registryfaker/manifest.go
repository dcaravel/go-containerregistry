// Copyright 2018 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package registryfaker

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type catalog struct {
	Repos []string `json:"repositories"`
}

type listTags struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type manifest struct {
	contentType string
	blob        []byte
}

type manifests struct {
	// maps repo -> manifest tag/digest -> manifest
	manifests map[string]map[string]manifest
	lock      sync.RWMutex
	log       *log.Logger
	handlers  []manifestHandler
}

func isManifest(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "manifests"
}

func isTags(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "tags"
}

func isCatalog(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 2 {
		return false
	}

	return elems[len(elems)-1] == "_catalog"
}

// Returns whether this url should be handled by the referrers handler
func isReferrers(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "referrers"
}

// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pulling-an-image-manifest
// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pushing-an-image
func (m *manifests) handle(resp http.ResponseWriter, req *http.Request) *regError {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	target := elem[len(elem)-1]
	repo := strings.Join(elem[1:len(elem)-2], "/")

	switch req.Method {
	case http.MethodGet:
		m.lock.RLock()
		defer m.lock.RUnlock()

		m.handleRequest(resp, req, repo, target)
		return nil

	case http.MethodHead:
		m.lock.RLock()
		defer m.lock.RUnlock()

		m.handleRequest(resp, req, repo, target)
		return nil

	case http.MethodPut:
		return &regError{
			Status:  http.StatusNotImplemented,
			Code:    "NOT_IMPLEMENTED",
			Message: "Method not implemented",
		}

	case http.MethodDelete:
		return &regError{
			Status:  http.StatusNotImplemented,
			Code:    "NOT_IMPLEMENTED",
			Message: "Method not implemented",
		}

	default:
		return &regError{
			Status:  http.StatusBadRequest,
			Code:    "METHOD_UNKNOWN",
			Message: "We don't understand your method + url",
		}
	}
}

func (m *manifests) handleRequest(resp http.ResponseWriter, req *http.Request, repo, target string) {
	for _, handler := range m.handlers {
		if handler.Handle(resp, req, repo, target) {
			// If the request was handled, stop processing handlers
			return
		}
	}
}

type manifestHandler interface {
	// Handle returns true if it handled the request
	Handle(resp http.ResponseWriter, req *http.Request, repo, target string) bool
}

type errorManifestHandler struct {
	Repo string
}

func (h *errorManifestHandler) Handle(resp http.ResponseWriter, req *http.Request, repo, target string) bool {
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
		return false
	}

	return true
}

const (
	DurPrefix = "dur-"
)

func extractKVFromTag(tag string) map[string]string {
	values := map[string]string{}
	allSplit := strings.Split(tag, "_") // underscore separates sets of key/value
	for _, kv := range allSplit {
		kvSplit := strings.Split(kv, "-") // dash separates key/value
		if len(kvSplit) < 2 {
			continue
		}
		k := kvSplit[0]
		v := kvSplit[1]
		values[k] = v
	}

	return values
}

type timeoutManifestHandler struct {
	Repo string
}

func (h *timeoutManifestHandler) Handle(resp http.ResponseWriter, req *http.Request, repo, target string) bool {
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
