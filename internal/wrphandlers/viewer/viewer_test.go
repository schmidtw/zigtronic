// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package viewer

import (
	"encoding/json"
	"io/fs"
	"os/user"
	"strconv"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/securly"
)

var testFS = fstest.MapFS{
	"dir/c.txt": &fstest.MapFile{
		Data:    []byte("c file content"),
		Mode:    0644,
		ModTime: time.Date(2022, 2, 2, 0, 0, 0, 0, time.UTC),
		Sys: func() *syscall.Stat_t {
			return &syscall.Stat_t{
				Uid: getCurrentUID(),
				Gid: getCurrentGID(),
			}
		}(),
	},
	"dir/a.txt": &fstest.MapFile{
		Data:    []byte("a file content"),
		Mode:    0644,
		ModTime: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	"dir/b.txt": &fstest.MapFile{
		Data:    []byte("b file content"),
		Mode:    0644,
		ModTime: time.Date(2021, 2, 2, 0, 0, 0, 0, time.UTC),
	},
	"file.txt": &fstest.MapFile{
		Data:    []byte("file content"),
		Mode:    0644,
		ModTime: time.Date(2021, 3, 3, 0, 0, 0, 0, time.UTC),
	},
}

func getCurrentGID() uint32 {
	current, err := user.Current()
	if err != nil {
		// Not running on a system that supports user.Current()
		return 0
	}

	gid, err := strconv.ParseUint(current.Gid, 10, 32)
	if err != nil {
		// This is just invalid.
		panic(err)
	}

	if gid > uint64(^uint32(0)) {
		// GID is too large to fit into a uint32
		panic("GID is too large to fit into a uint32")
	}

	return uint32(gid) // nolint:gosec
}

func getCurrentUID() uint32 {
	current, err := user.Current()
	if err != nil {
		// Not running on a system that supports user.Current()
		return 0
	}

	uid, err := strconv.ParseUint(current.Uid, 10, 32)
	if err != nil {
		// This is just invalid.
		panic(err)
	}

	return uint32(uid) // nolint:gosec
}

func getCurrentUser() string {
	current, err := user.Current()
	if err != nil {
		// Not running on a system that supports user.Current()
		return ""
	}

	return current.Name
}

func getCurrentGroup() string {
	current, err := user.Current()
	if err != nil {
		// Not running on a system that supports user.Current()
		return ""
	}

	grpInfo, err := user.LookupGroupId(current.Gid)
	if err != nil {
		return ""
	}

	return grpInfo.Name
}

func TestProcessMsg(t *testing.T) {
	tests := []struct {
		name     string
		cmd      Command
		expected map[string]securly.File
		err      error
	}{
		{
			name: "Valid Directory",
			cmd: Command{
				Path: "/dir",
			},
			expected: map[string]securly.File{
				"/dir/a.txt": {
					Mode:    testFS["dir/a.txt"].Mode,
					Size:    int64(len(testFS["dir/a.txt"].Data)),
					ModTime: testFS["dir/a.txt"].ModTime,
				},
				"/dir/b.txt": {
					Mode:    testFS["dir/b.txt"].Mode,
					Size:    int64(len(testFS["dir/b.txt"].Data)),
					ModTime: testFS["dir/b.txt"].ModTime,
				},
				"/dir/c.txt": {
					Mode:    testFS["dir/c.txt"].Mode,
					Size:    int64(len(testFS["dir/c.txt"].Data)),
					ModTime: testFS["dir/c.txt"].ModTime,
					UID:     getCurrentUID(),
					Owner:   getCurrentUser(),
					GID:     getCurrentGID(),
					Group:   getCurrentGroup(),
				},
			},
		},
		{
			name: "Valid (Root) Directory",
			cmd: Command{
				Path: "/",
			},
			expected: map[string]securly.File{
				"/dir": {
					Mode: 0555 | fs.ModeDir,
				},
				"/file.txt": {
					Mode:    testFS["file.txt"].Mode,
					Size:    int64(len(testFS["file.txt"].Data)),
					ModTime: testFS["file.txt"].ModTime,
				},
			},
		},
		{
			name: "Valid File",
			cmd: Command{
				Path: "/dir/a.txt",
			},
			expected: map[string]securly.File{
				"/dir/a.txt": {
					Mode:    testFS["dir/a.txt"].Mode,
					Size:    int64(len(testFS["dir/a.txt"].Data)),
					ModTime: testFS["dir/a.txt"].ModTime,
					Data:    testFS["dir/a.txt"].Data,
				},
			},
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
			assert := assert.New(t)
			require := require.New(t)

			h := Handler{
				root: testFS,
			}

			cmd, err := json.Marshal(tt.cmd)
			require.NoError(err)

			got, err := h.processMsg(cmd)
			if tt.err != nil {
				assert.ErrorIs(err, tt.err)
				assert.Nil(got)
				return
			}

			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.expected, got)
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
				ContentType: securly.SignedContentType,
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
