package registryfaker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
)

type remoteManifestHandler struct {
	Repo string
}

func (h *remoteManifestHandler) Handle(resp http.ResponseWriter, req *http.Request, repo, target string, mAccessor manifestAccessor, blobHandler BlobHandler) bool {
	fmt.Printf("Serving quay.io/%s/%s\n", repo, target)

	// Check storage for manifest
	mf, err := mAccessor.GetManifest(repo, target)
	if err == nil {
		fmt.Println("... from local cache!")
	}
	if err != nil {
		// Forward digests to blob storage
		if isDigest(target) {
			err.Write(resp)
			return true
		}
		// Get image from remote
		remoteMf, err := pullAndSaveImage(repo, target, mAccessor, blobHandler)
		if err != nil {
			return false
		}
		mf = *remoteMf
	}

	// Serve the manifest
	hash, _, _ := v1.SHA256(bytes.NewReader(mf.blob))
	resp.Header().Set("Docker-Content-Digest", hash.String())
	resp.Header().Set("Content-Type", mf.contentType)
	resp.Header().Set("Content-Length", fmt.Sprint(len(mf.blob)))
	resp.WriteHeader(http.StatusOK)
	io.Copy(resp, bytes.NewReader(mf.blob))

	return true
}

func pullAndSaveImage(repo string, target string, mAccessor manifestAccessor, bh BlobHandler) (*manifest, error) {
	ref, err := name.ParseReference(fmt.Sprintf("%s:%s", repo, target), name.WithDefaultRegistry("quay.io"))
	if err != nil {
		return nil, errors.Wrap(err, "Fatal error parsing ref")
	}
	img, err := remote.Image(ref)
	if err != nil {
		return nil, errors.Wrapf(err, "Fatal error pulling image %s:%s from quay.io\n", repo, target)
	}
	mraw, err := img.RawManifest()
	if err != nil {
		return nil, errors.Wrap(err, "Fatal error getting raw manifest")
	}
	mtype, err := img.MediaType()
	if err != nil {
		return nil, errors.Wrap(err, "Fatal error getting media type")
	}
	mf := manifest{
		blob:        mraw,
		contentType: string(mtype),
	}

	hash, _, _ := v1.SHA256(bytes.NewReader(mraw))
	mAccessor.PutManifest(repo, hash.String(), target, mf)

	bph := bh.(BlobPutHandler)

	// Put the image 'config' into blobs
	configHash, err := img.ConfigName()
	if err != nil {
		return nil, errors.Wrap(err, "Getting config")
	}

	configBytes, err := img.RawConfigFile()
	if err != nil {
		return nil, errors.Wrap(err, "getting config bytes")
	}

	err = bph.Put(context.Background(), repo, configHash, io.NopCloser(bytes.NewReader(configBytes)))
	if err != nil {
		return nil, errors.Wrap(err, "putting config into storage")
	}

	// Put the image layers into blobs
	layers, _ := img.Layers()
	for _, layer := range layers {
		hash, err := layer.Digest()
		if err != nil {
			return nil, errors.Wrap(err, "calcing digest")
		}

		reader, err := layer.Compressed()
		if err != nil {
			return nil, errors.Wrap(err, "compressing layer")
		}

		err = bph.Put(context.Background(), repo, hash, reader)
		if err != nil {
			return nil, errors.Wrap(err, "saving layer")
		}
	}

	return &mf, nil
}

// return nil, errors.Wrap(err, "")
