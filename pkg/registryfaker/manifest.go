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
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

var (
	EmptyManifest = manifest{}
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

type manifestHandler interface {
	// Handle returns true if it handled the request
	Handle(resp http.ResponseWriter, req *http.Request, repo, target string, mAccessor manifestAccessor, blobHandler BlobHandler) bool
}

type manifestAccessor interface {
	PutManifest(repo, digest, tag string, manifest manifest)
	GetManifest(repo, digest string) (manifest, *regError)
}
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

type randomManifestHandler struct {
	Repo string
}

func (h *randomManifestHandler) Handle(resp http.ResponseWriter, req *http.Request, repo, target string, mAccessor manifestAccessor, blobHandler BlobHandler) bool {
	if repo != h.Repo {
		return false
	}

	// Check the storage/cache for the manifest
	mf, rerr := mAccessor.GetManifest(repo, target)
	if rerr != nil {
		if isDigest(target) {
			rerr.Write(resp)
			return true
		}
	} else {
		// if we didn't get an error, that means a manifest was found
		hash, _, _ := v1.SHA256(bytes.NewReader(mf.blob))
		resp.Header().Set("Docker-Content-Digest", hash.String())
		resp.Header().Set("Content-Type", mf.contentType)
		resp.Header().Set("Content-Length", fmt.Sprint(len(mf.blob)))
		resp.WriteHeader(http.StatusOK)
		io.Copy(resp, bytes.NewReader(mf.blob))

		return true
	}

	kv := extractKVFromTag(target)
	layersRaw, ok := kv["layers"]
	if !ok {
		WriteErr(resp, http.StatusBadRequest, "BAD_REQUEST", "tag missing num layers")
		return true
	}

	sizeRaw, ok := kv["size"]
	if !ok {
		WriteErr(resp, http.StatusBadRequest, "BAD_REQUEST", "tag missing layer size")
		return true
	}

	seedRaw, ok := kv["seed"]
	if !ok {
		seedRaw = "0"
	}

	// imagesRaw, ok := kv["images"]
	// if !ok {
	// 	WriteErr(resp, http.StatusBadRequest, "BAD_REQUEST", "tag missing layer size")
	// 	return true
	// }

	numLayers, err := strconv.ParseInt(layersRaw, 10, 64)
	if err != nil {
		// default num layers
		numLayers = 1
	}

	layerSize, err := strconv.ParseInt(sizeRaw, 10, 64)
	if err != nil {
		// default num layers
		layerSize = 1024
	}

	seed, err := strconv.ParseInt(seedRaw, 10, 64)
	if err != nil {
		// default seed num
		seed = 0
	}

	img, err := random.Image(layerSize, numLayers, random.WithSource(rand.NewSource(seed)))
	if err != nil {
		regErrInternal(err).Write(resp)
		return true
	}

	manifestRaw, err := img.RawManifest()
	if err != nil {
		regErrInternal(err).Write(resp)
		return true
	}

	mtype, err := img.MediaType()
	if err != nil {
		regErrInternal(err).Write(resp)
		return true
	}

	mf = manifest{
		blob:        manifestRaw,
		contentType: string(mtype),
	}

	// manifest, _ := img.Manifest()
	// indent, _ := json.MarshalIndent(manifest, "", "  ")
	// log.Printf("manifest: %s\n", indent)

	// config, _ := img.ConfigFile()
	// indent, _ = json.MarshalIndent(config, "", "  ")
	// log.Printf("config: %s\n", indent)

	hash, _, _ := v1.SHA256(bytes.NewReader(manifestRaw))
	mAccessor.PutManifest(repo, hash.String(), target, mf)

	bph := blobHandler.(BlobPutHandler)

	// Put the image 'config' into blobs
	configHash, err := img.ConfigName()
	if err != nil {
		regErrInternal(err).Write(resp)
		return true
	}

	configBytes, err := img.RawConfigFile()
	if err != nil {
		regErrInternal(err).Write(resp)
		return true
	}

	err = bph.Put(context.Background(), repo, configHash, io.NopCloser(bytes.NewReader(configBytes)))
	if err != nil {
		regErrInternal(err).Write(resp)
		return true
	}

	// Put the image layers into blobs
	layers, _ := img.Layers()
	for _, layer := range layers {
		hash, err := layer.Digest()
		if err != nil {
			regErrInternal(err).Write(resp)
			return true
		}

		reader, err := layer.Compressed()
		if err != nil {
			regErrInternal(err).Write(resp)
			return true
		}

		err = bph.Put(context.Background(), repo, hash, reader)
		if err != nil {
			regErrInternal(err).Write(resp)
			return true
		}
	}

	// Respond with the image's info
	resp.Header().Set("Docker-Content-Digest", hash.String())
	resp.Header().Set("Content-Type", string(mtype))
	resp.Header().Set("Content-Length", fmt.Sprint(len(manifestRaw)))
	resp.WriteHeader(http.StatusOK)

	if req.Method == "GET" {
		// May not ever get here if ever GET is preceded by a HEAD
		io.Copy(resp, bytes.NewReader(manifestRaw))
		return true
	}

	return false
}
