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

	fmt.Printf("Target: %v\n", target)
	fmt.Printf("Repo: %v\n", repo)

	if target == "403" {
		return &regError{
			Status:  http.StatusForbidden,
			Code:    "FORBIDDEN",
			Message: "Fakereg: Access to this resource is forbidden",
		}
	}

	switch req.Method {
	case http.MethodGet:
		m.lock.RLock()
		defer m.lock.RUnlock()

		m.handleRequest(repo, target)

		resp.WriteHeader(http.StatusOK)
		return nil

	case http.MethodHead:
		m.lock.RLock()
		defer m.lock.RUnlock()

		m.handleRequest(repo, target)

		resp.WriteHeader(http.StatusOK)
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

func (m *manifests) handleRequest(repo string, target string) {
	m.log.Printf("Got request for %v:%v", repo, target)
}
