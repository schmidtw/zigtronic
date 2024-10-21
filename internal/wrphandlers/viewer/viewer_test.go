// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package viewer

import (
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/xmidt-org/wrp-go/v3"
)

const (
	aTxtContent = "a.txt content"
	bTxtContent = "b.txt content is longer"
	cTxtContent = "c.txt content"
	fileContent = "This is a test file content."

	aTxtInfo = `{` +
		`"name":"a.txt",` +
		`"mode":"-rw-r--r--",` +
		`"size":13,` +
		`"mt":"2021-01-01T00:00:00Z"` +
		`}`

	bTxtInfo = `{` +
		`"name":"b.txt",` +
		`"mode":"-rw-r--r--",` +
		`"size":23,` +
		`"mt":"2021-02-02T00:00:00Z"` +
		`}`

	cTxtInfo = `{` +
		`"name":"c.txt",` +
		`"mode":"-rw-r--r--",` +
		`"size":13,` +
		`"mt":"2022-02-02T00:00:00Z"` +
		`}`

	fileInfo = `{` +
		`"name":"file.txt",` +
		`"mode":"-rw-r--r--",` +
		`"size":28,` +
		`"mt":"2021-03-03T00:00:00Z"` +
		`}`

	dirInfo = `{` +
		`"name":"dir",` +
		`"mode":"dr-xr-xr-x",` +
		`"size":0,` +
		`"mt":"0001-01-01T00:00:00Z"` +
		`}`
)

var testFS = fstest.MapFS{
	"dir/c.txt": &fstest.MapFile{
		Data:    []byte(cTxtContent),
		Mode:    0644,
		ModTime: time.Date(2022, 2, 2, 0, 0, 0, 0, time.UTC),
	},
	"dir/a.txt": &fstest.MapFile{
		Data:    []byte(aTxtContent),
		Mode:    0644,
		ModTime: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	"dir/b.txt": &fstest.MapFile{
		Data:    []byte(bTxtContent),
		Mode:    0644,
		ModTime: time.Date(2021, 2, 2, 0, 0, 0, 0, time.UTC),
	},
	"file.txt": &fstest.MapFile{
		Data:    []byte(fileContent),
		Mode:    0644,
		ModTime: time.Date(2021, 3, 3, 0, 0, 0, 0, time.UTC),
	},
}

func TestProcessMsg(t *testing.T) {
	tests := []struct {
		name        string
		cmd         Command
		expected    string
		contentType string
		err         error
	}{
		{
			name: "Valid Directory",
			cmd: Command{
				Path: "/dir",
			},
			contentType: "application/json",
			expected: `[` +
				aTxtInfo + `,` +
				bTxtInfo + `,` +
				cTxtInfo +
				`]`,
		}, {
			name: "Valid (Root) Directory",
			cmd: Command{
				Path: "/",
			},
			contentType: "application/json",
			expected: `[` +
				dirInfo + `,` +
				fileInfo +
				`]`,
		}, {
			name:        "Valid File",
			contentType: "application/octet-stream",
			cmd: Command{
				Path: "/dir/a.txt",
			},
			expected: aTxtContent,
		}, {
			name: "Invalid Path",
			cmd: Command{
				Path: "/invalid",
			},
			err: fs.ErrNotExist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &wrp.Message{}
			h := Handler{
				root: testFS,
			}
			err := h.processMsg(tt.cmd, resp)
			if tt.err != nil {
				assert.ErrorIs(t, err, tt.err)
				assert.Empty(t, resp.Payload)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.contentType, resp.ContentType)
				switch tt.contentType {
				case "application/json":
					assert.JSONEq(t, tt.expected, string(resp.Payload))
				default:
					assert.Equal(t, tt.expected, string(resp.Payload))
				}
			}
		})
	}
}

/*
func TestHandleWrp(t *testing.T) {
	tests := []struct {
		name     string
		msg      wrp.Message
		expected wrp.Message
		err      error
	}{
		{
			name: "Valid JSON Command",
			msg: wrp.Message{
				Source:      "source",
				Destination: "destination",
				ContentType: "application/json",
				Payload:     []byte(`{"path":"/valid/directory","max_size":0}`),
			},
			expected: wrp.Message{
				Source:      "destination",
				Destination: "source",
				ContentType: "application/json",
				Payload:     []byte(`[{"Name":"file1","Size":123},{"Name":"file2","Size":456}]`),
			},
			err: nil,
		},
		{
			name: "Invalid Content Type",
			msg: wrp.Message{
				Source:      "source",
				Destination: "destination",
				ContentType: "text/plain",
			},
			expected: wrp.Message{
				Source:      "destination",
				Destination: "source",
				ContentType: "application/text",
				Payload:     []byte("invalid content type"),
			},
			err: errors.New("invalid content type"),
		},
		{
			name: "Invalid JSON Command",
			msg: wrp.Message{
				Source:      "source",
				Destination: "destination",
				ContentType: "application/json",
				Payload:     []byte(`{"path":"/invalid/json"`),
			},
			expected: wrp.Message{
				Source:      "destination",
				Destination: "source",
				ContentType: "application/text",
				Payload:     []byte("unexpected end of JSON input"),
			},
			err: errors.New("unexpected end of JSON input"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{
				egress: mockEgressHandler{},
			}
			err := h.HandleWrp(tt.msg)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type mockEgressHandler struct{}

func (m mockEgressHandler) HandleWrp(msg wrp.Message) error {
	return nil
}
*/
