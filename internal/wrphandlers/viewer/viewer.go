// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package viewer

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/fs"
	"os/user"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/xmidt-org/securly"
	"github.com/xmidt-org/wrp-go/v3"
	"github.com/xmidt-org/xmidt-agent/internal/wrpkit"
)

const defaultMaxFileSize = 1000

type Handler struct {
	egress       wrpkit.Handler
	root         fs.FS
	trustedRoots []*x509.Certificate
	policies     []string
}

type Option interface {
	apply(*Handler) error
}

type optionFunc func(*Handler) error

func (f optionFunc) apply(h *Handler) error {
	return f(h)
}

// New creates a new instance of the Handler struct.  The parameter egress is
// the handler that will be called to send the response.  The parameter source is the source to use in
// the response message. This handler handles crud messages specifically for xmdit-agent, only.
func New(egress wrpkit.Handler, opts ...Option) (*Handler, error) {
	h := Handler{
		egress: egress,
	}

	opts = append(opts, validate())

	for _, opt := range opts {
		if opt != nil {
			err := opt.apply(&h)
			if err != nil {
				return nil, err
			}
		}
	}

	return &h, nil
}

type Command struct {
	Path    string `json:"path"`
	MaxSize int    `json:"max_size"`
}

func (h *Handler) isDir(path string) (bool, error) {
	fileInfo, err := fs.Stat(h.root, path)
	if err != nil {
		return false, err
	}

	return fileInfo.IsDir(), nil
}

func (h Handler) readDir(fp, op string) (map[string]securly.File, error) {
	files, err := fs.ReadDir(h.root, fp)
	if err != nil {
		return nil, err
	}

	rv := make(map[string]securly.File, len(files))
	for _, file := range files {
		info, err := file.Info()
		if err != nil {
			return nil, err
		}

		entry := fileInfoToFile(info)

		rv[path.Join(op, file.Name())] = entry
	}

	return rv, nil
}

func (h *Handler) readFile(path string, max int) (securly.File, error) {
	file, err := h.root.Open(path)
	if err != nil {
		return securly.File{}, err
	}
	defer file.Close()

	fi, err := file.Stat()
	if err != nil {
		return securly.File{}, err
	}

	rv := fileInfoToFile(fi)

	buffer := make([]byte, max)
	n, err := file.Read(buffer)
	if err != nil {
		return securly.File{}, err
	}

	rv.Data = buffer[:n]

	return rv, nil
}

func (h *Handler) HandleWrp(msg wrp.Message) error {
	if msg.Type != wrp.SimpleRequestResponseMessageType {
		return errors.New("invalid message type")
	}

	response := wrp.Message{
		Source:          msg.Destination,
		Destination:     msg.Source,
		TransactionUUID: msg.TransactionUUID,
	}

	switch msg.ContentType {
	case securly.EncryptedContentType, securly.SignedContentType:
	default:
		return errors.New("invalid content type")
	}

	decoded, err := securly.Decode(msg.Payload,
		securly.TrustRootCAs(h.trustedRoots...),
		securly.RequirePolicies(h.policies...))
	if err != nil {
		return err
	}

	files, err := h.processMsg(decoded.Payload)
	if err != nil {
		return h.sendError(err, response)
	}

	data, isEncrypted, err := securly.Message{
		Files:    files,
		Response: decoded.Response,
	}.Encode()
	if err != nil {
		return h.sendError(err, response)
	}

	ct := securly.SignedContentType
	if isEncrypted {
		ct = securly.EncryptedContentType
	}
	response.ContentType = ct
	response.Payload = data

	return h.egress.HandleWrp(response)
}

func (h *Handler) sendError(err error, response wrp.Message) error {
	response.Payload = []byte(err.Error())
	response.ContentType = "application/text"
	return h.egress.HandleWrp(response)
}

func (h *Handler) processMsg(in []byte) (map[string]securly.File, error) {
	var cmd Command
	err := json.Unmarshal(in, &cmd)
	if err != nil {
		return nil, err
	}

	path := cmd.Path
	path = strings.TrimSpace(path)

	originalPath := path

	if path == "/" {
		path = "."
	}
	path = strings.TrimPrefix(path, "/")
	if !fs.ValidPath(path) {
		return nil, errors.New("invalid path")
	}

	dir, err := h.isDir(path)
	if err != nil {
		return nil, err
	}

	if dir {
		return h.readDir(path, originalPath)
	}

	size := defaultMaxFileSize
	if cmd.MaxSize > 0 {
		size = cmd.MaxSize
	}

	file, err := h.readFile(path, size)
	if err != nil {
		return nil, err
	}

	return map[string]securly.File{
		originalPath: file,
	}, nil
}

func fileInfoToFile(fi fs.FileInfo) securly.File {
	rv := securly.File{
		Size:    fi.Size(),
		Mode:    fi.Mode(),
		ModTime: fi.ModTime(),
	}

	// Access system-specific information
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if ok {
		rv.UID = stat.Uid
		rv.GID = stat.Gid

		uidStr := strconv.FormatUint(uint64(stat.Uid), 10)
		if userInfo, err := user.LookupId(uidStr); err == nil {
			rv.Owner = userInfo.Name
		}

		gidStr := strconv.FormatUint(uint64(stat.Gid), 10)
		if grpInfo, err := user.LookupGroupId(gidStr); err == nil {
			rv.Group = grpInfo.Name
		}
	}

	return rv
}
