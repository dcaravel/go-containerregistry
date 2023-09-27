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
	"log"
	"net/http"
	"strings"
	"sync"
)

var (
	EmptyManifest = manifest{}
)

// type catalog struct {
// 	Repos []string `json:"repositories"`
// }

// type listTags struct {
// 	Name string   `json:"name"`
// 	Tags []string `json:"tags"`
// }

type manifest struct {
	contentType string
	blob        []byte
}

type manifests struct {
	// maps repo -> manifest tag/digest -> manifest
	manifests   map[string]map[string]manifest
	lock        sync.RWMutex
	log         *log.Logger
	handlers    []manifestHandler
	blobHandler BlobHandler
}

func isManifest(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "manifests"
}

// func isTags(req *http.Request) bool {
// 	elems := strings.Split(req.URL.Path, "/")
// 	elems = elems[1:]
// 	if len(elems) < 4 {
// 		return false
// 	}
// 	return elems[len(elems)-2] == "tags"
// }

// func isCatalog(req *http.Request) bool {
// 	elems := strings.Split(req.URL.Path, "/")
// 	elems = elems[1:]
// 	if len(elems) < 2 {
// 		return false
// 	}

// 	return elems[len(elems)-1] == "_catalog"
// }

// Returns whether this url should be handled by the referrers handler
// func isReferrers(req *http.Request) bool {
// 	elems := strings.Split(req.URL.Path, "/")
// 	elems = elems[1:]
// 	if len(elems) < 4 {
// 		return false
// 	}
// 	return elems[len(elems)-2] == "referrers"
// }

// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pulling-an-image-manifest
// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pushing-an-image
func (m *manifests) handle(resp http.ResponseWriter, req *http.Request) *regError {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	target := elem[len(elem)-1]
	repo := strings.Join(elem[1:len(elem)-2], "/")

	switch req.Method {
	case http.MethodGet:
		m.handleRequest(resp, req, repo, target)
		return nil

	case http.MethodHead:
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
		if handler.Handle(resp, req, repo, target, m, m.blobHandler) {
			// If the request was handled, stop processing handlers
			return
		}
	}
}

func (m *manifests) PutManifest(repo, digest, tag string, mf manifest) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.manifests[repo]; !ok {
		m.manifests[repo] = make(map[string]manifest, 2)
	}

	m.manifests[repo][digest] = mf
	m.manifests[repo][tag] = mf

	log.Printf("manifest upserted %v %v", repo, digest)
}

func (m *manifests) GetManifest(repo, digest string) (manifest, *regError) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	c, ok := m.manifests[repo]
	if !ok {
		return EmptyManifest, &regError{
			Status:  http.StatusNotFound,
			Code:    "NAME_UNKNOWN",
			Message: "Unknown name",
		}
	}

	mf, ok := c[digest]
	if !ok {
		return EmptyManifest, &regError{
			Status:  http.StatusNotFound,
			Code:    "MANIFEST_UNKNOWN",
			Message: "Unknown manifest",
		}
	}

	return mf, nil
}
