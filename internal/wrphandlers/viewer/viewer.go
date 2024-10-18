// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package viewer

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/xmidt-org/wrp-go/v3"
	"github.com/xmidt-org/xmidt-agent/internal/wrpkit"
)

const maxFileSize = 1000

type Handler struct {
	egress wrpkit.Handler
	public []rsa.PublicKey
}

// New creates a new instance of the Handler struct.  The parameter egress is
// the handler that will be called to send the response.  The parameter source is the source to use in
// the response message. This handler handles crud messages specifically for xmdit-agent, only.
func New(egress wrpkit.Handler, public []rsa.PublicKey) (*Handler, error) {
	h := Handler{
		egress: egress,
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
	ModTime string `json:"touched"`
}

func isDir(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	return fileInfo.IsDir(), nil
}

func readDir(path string) ([]FileInfo, error) {
	files, err := os.ReadDir(path)
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

func readFile(path string, max int) ([]byte, error) {
	file, err := os.Open(path)
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

	err = processMsg(cmd, &response)

done:
	if err != nil {
		response.Payload = []byte(err.Error())
		response.ContentType = "application/text"
	}

	return h.egress.HandleWrp(response)
}

func processMsg(cmd Command, resp *wrp.Message) error {
	l, err := wrp.ParseLocator(cmd.Path)
	if err != nil {
		return err
	}

	path := l.Ignored

	if path == "" {
		return errors.New("invalid path")
	}

	dir, err := isDir(path)
	if err != nil {
		return err
	}

	if dir {
		fileInfos, err := readDir(path)
		if err != nil {
			return err
		}

		resp.Payload, err = json.Marshal(fileInfos)
		if err != nil {
			return err
		}
		resp.ContentType = "application/json"
		return nil
	}

	size := maxFileSize
	if cmd.MaxSize > 0 {
		size = cmd.MaxSize
	}

	buf, err := readFile(path, size)
	if err != nil {
		return err
	}

	resp.Payload = buf
	resp.ContentType = "application/octet-stream"

	return err
}
