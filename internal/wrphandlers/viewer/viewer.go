// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package viewer

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/xmidt-org/wrp-go/v3"
	"github.com/xmidt-org/xmidt-agent/internal/wrpkit"
)

const defaultMaxFileSize = 1000

type Handler struct {
	egress wrpkit.Handler
	root   fs.FS
	public []rsa.PublicKey
}

// New creates a new instance of the Handler struct.  The parameter egress is
// the handler that will be called to send the response.  The parameter source is the source to use in
// the response message. This handler handles crud messages specifically for xmdit-agent, only.
func New(egress wrpkit.Handler, root fs.FS, public []rsa.PublicKey) (*Handler, error) {
	h := Handler{
		egress: egress,
		root:   root,
		public: public,
	}

	return &h, nil
}

type Command struct {
	Path    string `json:"path"`
	MaxSize int    `json:"max_size"`
}

type FileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime string `json:"mt"`
}

// FileInfoSlice is a type for a slice of FileInfo that implements sort.Interface
type FileInfoSlice []FileInfo

func (f FileInfoSlice) Len() int {
	return len(f)
}

func (f FileInfoSlice) Less(i, j int) bool {
	return f[i].Name < f[j].Name
}

func (f FileInfoSlice) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}

func (h *Handler) isDir(path string) (bool, error) {
	fileInfo, err := fs.Stat(h.root, path)
	if err != nil {
		return false, err
	}

	return fileInfo.IsDir(), nil
}

func (h *Handler) readDir(path string) ([]FileInfo, error) {
	files, err := fs.ReadDir(h.root, path)
	if err != nil {
		return nil, err
	}

	fileInfos := make([]FileInfo, 0, len(files))
	for _, file := range files {
		fi, err := file.Info()
		if err != nil {
			return nil, err
		}

		fileInfos = append(fileInfos, FileInfo{
			Name:    file.Name(),
			Size:    fi.Size(),
			Mode:    fi.Mode().String(),
			ModTime: fi.ModTime().Format(time.RFC3339),
		})
	}
	return fileInfos, nil
}

func (h *Handler) readFile(path string, max int) ([]byte, error) {
	file, err := h.root.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buffer := make([]byte, max)
	n, err := file.Read(buffer)
	if err != nil {
		return nil, err
	}
	return buffer[:n], nil
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

	if msg.ContentType != "application/json" {
		return errors.New("invalid content type")
	}

	// TODO: Add msg.Sig so each WRP message can be signed/validated

	var cmd Command
	err := json.Unmarshal(msg.Payload, &cmd)
	if err != nil {
		goto done
	}

	err = h.processMsg(cmd, &response)

done:
	if err != nil {
		response.Payload = []byte(err.Error())
		response.ContentType = "application/text"
	}

	return h.egress.HandleWrp(response)
}

func (h *Handler) processMsg(cmd Command, resp *wrp.Message) error {

	path := cmd.Path
	path = strings.TrimSpace(path)

	if path == "/" {
		path = "."
	}
	path = strings.TrimPrefix(path, "/")
	if !fs.ValidPath(path) {
		return errors.New("invalid path")
	}

	dir, err := h.isDir(path)
	if err != nil {
		return err
	}

	if dir {
		fileInfos, err := h.readDir(path)
		if err != nil {
			return err
		}

		// sort the fileInfos by name
		list := FileInfoSlice(fileInfos)
		sort.Sort(list)

		resp.Payload, err = json.Marshal(list)
		if err != nil {
			return err
		}
		resp.ContentType = "application/json"
		return nil
	}

	size := defaultMaxFileSize
	if cmd.MaxSize > 0 {
		size = cmd.MaxSize
	}

	buf, err := h.readFile(path, size)
	if err != nil {
		return err
	}

	resp.Payload = buf
	resp.ContentType = "application/octet-stream"
	return nil
}
