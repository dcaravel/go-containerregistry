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

// Package registry implements a docker V2 registry and the OCI distribution specification.
//
// It is designed to be used anywhere a low dependency container registry is needed, with an
// initial focus on tests.
//
// Its goal is to be standards compliant and its strictness will increase over time.
//
// This is currently a low flightmiles system. It's likely quite safe to use in tests; If you're using it
// in production, please let us know how and send us CL's for integration tests.
package registryfaker

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"
)

const (
	RepoPrefix = "broken"
)

type registry struct {
	log              *log.Logger
	referrersEnabled bool
	blobs            blobs
	manifests        manifests
	warnings         map[float64]string
	catalogDur       time.Duration
}

// https://docs.docker.com/registry/spec/api/#api-version-check
// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#api-version-check
func (r *registry) v2(resp http.ResponseWriter, req *http.Request) *regError {
	if r.warnings != nil {
		rnd := rand.Float64()
		for prob, msg := range r.warnings {
			if prob > rnd {
				resp.Header().Add("Warning", fmt.Sprintf(`299 - "%s"`, msg))
			}
		}
	}

	if isBlob(req) {
		return r.blobs.handle(resp, req)
	}
	if isManifest(req) {
		return r.manifests.handle(resp, req)
	}
	// if isTags(req) {
	// 	return r.manifests.handleTags(resp, req)
	// }

	if r.catalogDur > 0 {
		if isCatalog(req) {
			r.log.Printf("Catalog request, sleeping for %s", r.catalogDur)
			time.Sleep(r.catalogDur)
		}
	}

	// if r.referrersEnabled && isReferrers(req) {
	// 	return r.manifests.handleReferrers(resp, req)
	// }
	resp.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	if req.URL.Path != "/v2/" && req.URL.Path != "/v2" {
		return &regError{
			Status:  http.StatusNotFound,
			Code:    "METHOD_UNKNOWN",
			Message: "I don't understand your request + URL",
		}
	}
	resp.WriteHeader(200)
	return nil
}

func (r *registry) root(resp http.ResponseWriter, req *http.Request) {
	if rerr := r.v2(resp, req); rerr != nil {
		r.log.Printf("%s %s %d %s %s", req.Method, req.URL, rerr.Status, rerr.Code, rerr.Message)
		rerr.Write(resp)
		return
	}
	r.log.Printf("%s %s", req.Method, req.URL)
}

// New returns a handler which implements the docker registry protocol.
// It should be registered at the site root.
func New(opts ...Option) http.Handler {
	blobHandler := &memHandler{m: map[string][]byte{}}

	log := log.New(os.Stderr, "", log.LstdFlags)
	var catalogDuration time.Duration
	if v := os.Getenv("V2_CATALOG_DELAY"); v != "" {
		dur, err := time.ParseDuration(v)
		if err != nil {
			log.Printf("Error parsing env V2_CATALOG_DELAY: %v", err)

		} else {
			catalogDuration = dur
		}
	}

	r := &registry{
		log: log,
		blobs: blobs{
			blobHandler: blobHandler,
			uploads:     map[string][]byte{},
			log:         log,
		},
		manifests: manifests{
			manifests:   map[string]map[string]manifest{},
			log:         log,
			blobHandler: blobHandler,
			handlers: []manifestHandler{
				&errorManifestHandler{Repo: fmt.Sprintf("%s/error", RepoPrefix)},
				&timeoutManifestHandler{Repo: fmt.Sprintf("%s/timeout", RepoPrefix)},
				&randomManifestHandler{Repo: fmt.Sprintf("%s/random", RepoPrefix)},
				&preparedManifestHandler{Repo: fmt.Sprintf("%s/prepared", RepoPrefix)},
				&remoteManifestHandler{Repo: "*"}, // ALWAYS keep this handler last, it's a match any
			},
		},
		catalogDur: catalogDuration,
	}

	for _, o := range opts {
		o(r)
	}
	return http.HandlerFunc(r.root)
}

// Option describes the available options
// for creating the registry.
type Option func(r *registry)

// Logger overrides the logger used to record requests to the registry.
func Logger(l *log.Logger) Option {
	return func(r *registry) {
		r.log = l
		// r.manifests.log = l
		// r.blobs.log = l
	}
}

// WithReferrersSupport enables the referrers API endpoint (OCI 1.1+)
func WithReferrersSupport(enabled bool) Option {
	return func(r *registry) {
		r.referrersEnabled = enabled
	}
}

func WithWarning(prob float64, msg string) Option {
	return func(r *registry) {
		if r.warnings == nil {
			r.warnings = map[float64]string{}
		}
		r.warnings[prob] = msg
	}
}

func WithBlobHandler(h BlobHandler) Option {
	return func(r *registry) {
		r.blobs.blobHandler = h
		r.manifests.blobHandler = h
	}
}
