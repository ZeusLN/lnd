// Code generated by protoc-gen-grpc-gateway. DO NOT EDIT.
// source: stateservice.proto

/*
Package lnrpc is a reverse proxy.

It translates gRPC into RESTful JSON APIs.
*/
package lnrpc

import (
	"context"
	"io"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/grpc-ecosystem/grpc-gateway/v2/utilities"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Suppress "imported and not used" errors
var _ codes.Code
var _ io.Reader
var _ status.Status
var _ = runtime.String
var _ = utilities.NewDoubleArray
var _ = metadata.Join

func request_State_SubscribeState_0(ctx context.Context, marshaler runtime.Marshaler, client StateClient, req *http.Request, pathParams map[string]string) (State_SubscribeStateClient, runtime.ServerMetadata, error) {
	var protoReq SubscribeStateRequest
	var metadata runtime.ServerMetadata

	stream, err := client.SubscribeState(ctx, &protoReq)
	if err != nil {
		return nil, metadata, err
	}
	header, err := stream.Header()
	if err != nil {
		return nil, metadata, err
	}
	metadata.HeaderMD = header
	return stream, metadata, nil

}

func request_State_GetState_0(ctx context.Context, marshaler runtime.Marshaler, client StateClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq GetStateRequest
	var metadata runtime.ServerMetadata

	msg, err := client.GetState(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_State_GetState_0(ctx context.Context, marshaler runtime.Marshaler, server StateServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq GetStateRequest
	var metadata runtime.ServerMetadata

	msg, err := server.GetState(ctx, &protoReq)
	return msg, metadata, err

}

// RegisterStateHandlerServer registers the http handlers for service State to "mux".
// UnaryRPC     :call StateServer directly.
// StreamingRPC :currently unsupported pending https://github.com/grpc/grpc-go/issues/906.
// Note that using this registration option will cause many gRPC library features to stop working. Consider using RegisterStateHandlerFromEndpoint instead.
// GRPC interceptors will not work for this type of registration. To use interceptors, you must use the "runtime.WithMiddlewares" option in the "runtime.NewServeMux" call.
func RegisterStateHandlerServer(ctx context.Context, mux *runtime.ServeMux, server StateServer) error {

	mux.Handle("GET", pattern_State_SubscribeState_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		err := status.Error(codes.Unimplemented, "streaming calls are not yet supported in the in-process transport")
		_, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
		return
	})

	mux.Handle("GET", pattern_State_GetState_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateIncomingContext(ctx, mux, req, "/lnrpc.State/GetState", runtime.WithHTTPPathPattern("/v1/state"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_State_GetState_0(annotatedContext, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_State_GetState_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	return nil
}

// RegisterStateHandlerFromEndpoint is same as RegisterStateHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterStateHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
	conn, err := grpc.NewClient(endpoint, opts...)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if cerr := conn.Close(); cerr != nil {
				grpclog.Errorf("Failed to close conn to %s: %v", endpoint, cerr)
			}
			return
		}
		go func() {
			<-ctx.Done()
			if cerr := conn.Close(); cerr != nil {
				grpclog.Errorf("Failed to close conn to %s: %v", endpoint, cerr)
			}
		}()
	}()

	return RegisterStateHandler(ctx, mux, conn)
}

// RegisterStateHandler registers the http handlers for service State to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterStateHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return RegisterStateHandlerClient(ctx, mux, NewStateClient(conn))
}

// RegisterStateHandlerClient registers the http handlers for service State
// to "mux". The handlers forward requests to the grpc endpoint over the given implementation of "StateClient".
// Note: the gRPC framework executes interceptors within the gRPC handler. If the passed in "StateClient"
// doesn't go through the normal gRPC flow (creating a gRPC client etc.) then it will be up to the passed in
// "StateClient" to call the correct interceptors. This client ignores the HTTP middlewares.
func RegisterStateHandlerClient(ctx context.Context, mux *runtime.ServeMux, client StateClient) error {

	mux.Handle("GET", pattern_State_SubscribeState_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateContext(ctx, mux, req, "/lnrpc.State/SubscribeState", runtime.WithHTTPPathPattern("/v1/state/subscribe"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_State_SubscribeState_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_State_SubscribeState_0(annotatedContext, mux, outboundMarshaler, w, req, func() (proto.Message, error) { return resp.Recv() }, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("GET", pattern_State_GetState_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateContext(ctx, mux, req, "/lnrpc.State/GetState", runtime.WithHTTPPathPattern("/v1/state"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_State_GetState_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_State_GetState_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	return nil
}

var (
	pattern_State_SubscribeState_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2}, []string{"v1", "state", "subscribe"}, ""))

	pattern_State_GetState_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"v1", "state"}, ""))
)

var (
	forward_State_SubscribeState_0 = runtime.ForwardResponseStream

	forward_State_GetState_0 = runtime.ForwardResponseMessage
)
