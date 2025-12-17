package logger

import (
	"context"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type wrappedClientStreamLogger struct {
	grpc.ClientStream
	ctx       context.Context
	reqID     string
	method    string
	target    string
	startTime time.Time
}

func (w *wrappedClientStreamLogger) Context() context.Context {
	return w.ctx
}

func (w *wrappedClientStreamLogger) SendMsg(m any) error {
	err := w.ClientStream.SendMsg(m)

	if err != nil {
		duration := time.Since(w.startTime)
		statusCode := status.Code(err)

		logrus.WithFields(logrus.Fields{
			"requestID":  w.reqID,
			"took":       duration,
			"method":     w.method,
			"target":     w.target,
			"statusCode": statusCode,
			"error":      err.Error(),
		}).Errorf("client: failed to send message in stream")
	} else {
		logrus.WithField("requestID", w.reqID).Debugf("client: sent message in stream %s", w.method)
	}
	return err
}

func (w *wrappedClientStreamLogger) RecvMsg(m any) error {
	err := w.ClientStream.RecvMsg(m)

	if err != nil {
		if err != io.EOF {
			duration := time.Since(w.startTime)
			statusCode := status.Code(err)

			logrus.WithFields(logrus.Fields{
				"requestID":  w.reqID,
				"took":       duration,
				"method":     w.method,
				"target":     w.target,
				"statusCode": statusCode,
				"error":      err.Error(),
			}).Errorf("client: failed to receive message in stream")
		}
	} else {
		logrus.WithField("requestID", w.reqID).Debugf("client: received message in stream %s", w.method)
	}
	return err
}

func ClientRequestIDInterceptor(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	requestID, ok := ctx.Value("requestID").(string)
	if !ok {
		requestID = uuid.NewString()
		ctx = context.WithValue(ctx, "requestID", requestID)
	}

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	}

	md.Append("x-request-id", requestID)
	newCtx := metadata.NewOutgoingContext(ctx, md)

	logrus.WithField("requestID", requestID).Debugf("client: outgoing request to %s, method: %s", cc.Target(), method)

	return invoker(newCtx, method, req, reply, cc, opts...)
}

func ClientLoggingInterceptor(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	requestID, ok := ctx.Value("requestID").(string)
	if !ok {
		requestID = "no-request-id"
	}

	startTime := time.Now()
	logrus.WithField("requestID", requestID).Infof("client: sending gRPC request: %s (target: %s)", method, cc.Target())

	err := invoker(ctx, method, req, reply, cc, opts...)

	duration := time.Since(startTime)
	statusCode := status.Code(err)

	logFields := logrus.Fields{
		"requestID":  requestID,
		"took":       duration,
		"method":     method,
		"statusCode": statusCode,
		"target":     cc.Target(),
	}

	if err != nil {
		logFields["error"] = err.Error()
		logrus.WithFields(logFields).Errorf("client: gRPC request failed")
	} else {
		logrus.WithFields(logFields).Infof("client: gRPC request completed successfully")
	}

	return err
}

func ClientStreamInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	requestID, ok := ctx.Value("requestID").(string)
	if !ok {
		requestID = uuid.NewString()
		ctx = context.WithValue(ctx, "requestID", requestID)
	}

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	}

	md.Append("x-request-id", requestID)
	newCtx := metadata.NewOutgoingContext(ctx, md)

	startTime := time.Now()
	logrus.WithField("requestID", requestID).Infof("client: initiating stream: %s (target: %s)", method, cc.Target())

	actualClientStream, err := streamer(newCtx, desc, cc, method, opts...)
	if err != nil {
		logrus.WithField("requestID", requestID).Errorf("client: failed to call streamer function: %v", err)

		return nil, err
	}

	if actualClientStream == nil {
		logrus.WithField("requestID", requestID).Errorf("client: streamer function returned nil ClientStream")

		return nil, err
	}

	if _, ok := actualClientStream.(*wrappedClientStreamLogger); ok {
		return actualClientStream, nil
	}

	wrapped := &wrappedClientStreamLogger{
		ClientStream: actualClientStream,
		ctx:          newCtx,
		reqID:        requestID,
		method:       method,
		target:       cc.Target(),
		startTime:    startTime,
	}

	return wrapped, nil
}
