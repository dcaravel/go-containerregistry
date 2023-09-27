package registryfaker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

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
