//go:build viewer
// +build viewer

// SPDX-FileCopyrightText: 2024 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"

	"github.com/xmidt-org/xmidt-agent/internal/pubsub"
	"github.com/xmidt-org/xmidt-agent/internal/wrphandlers/viewer"
	"go.uber.org/fx"
)

type viewerIn struct {
	fx.In

	FilesystemViewer FilesystemViewer

	PubSub *pubsub.PubSub
}

type viewerOut struct {
	fx.Out
	Cancel func() `group:"cancels"`
}

func provideViewerHandler(in viewerIn) (viewerOut, error) {
	viewerHandler, err := viewer.New(in.PubSub, nil)
	if err != nil {
		return viewerOut{}, errors.Join(ErrWRPHandlerConfig, err)
	}

	viewer, err := in.PubSub.SubscribeService("/viewer", viewerHandler)
	if err != nil {
		return viewerOut{}, errors.Join(ErrWRPHandlerConfig, err)
	}

	return viewerOut{
		Cancel: viewer,
	}, nil
}
