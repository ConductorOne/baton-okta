// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             (unknown)
// source: c1/connectorapi/baton/v1/config.proto

package v1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	ConnectorConfigService_GetConnectorConfig_FullMethodName = "/c1.connectorapi.baton.v1.ConnectorConfigService/GetConnectorConfig"
)

// ConnectorConfigServiceClient is the client API for ConnectorConfigService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ConnectorConfigServiceClient interface {
	GetConnectorConfig(ctx context.Context, in *GetConnectorConfigRequest, opts ...grpc.CallOption) (*GetConnectorConfigResponse, error)
}

type connectorConfigServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewConnectorConfigServiceClient(cc grpc.ClientConnInterface) ConnectorConfigServiceClient {
	return &connectorConfigServiceClient{cc}
}

func (c *connectorConfigServiceClient) GetConnectorConfig(ctx context.Context, in *GetConnectorConfigRequest, opts ...grpc.CallOption) (*GetConnectorConfigResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetConnectorConfigResponse)
	err := c.cc.Invoke(ctx, ConnectorConfigService_GetConnectorConfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ConnectorConfigServiceServer is the server API for ConnectorConfigService service.
// All implementations should embed UnimplementedConnectorConfigServiceServer
// for forward compatibility.
type ConnectorConfigServiceServer interface {
	GetConnectorConfig(context.Context, *GetConnectorConfigRequest) (*GetConnectorConfigResponse, error)
}

// UnimplementedConnectorConfigServiceServer should be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedConnectorConfigServiceServer struct{}

func (UnimplementedConnectorConfigServiceServer) GetConnectorConfig(context.Context, *GetConnectorConfigRequest) (*GetConnectorConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetConnectorConfig not implemented")
}
func (UnimplementedConnectorConfigServiceServer) testEmbeddedByValue() {}

// UnsafeConnectorConfigServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ConnectorConfigServiceServer will
// result in compilation errors.
type UnsafeConnectorConfigServiceServer interface {
	mustEmbedUnimplementedConnectorConfigServiceServer()
}

func RegisterConnectorConfigServiceServer(s grpc.ServiceRegistrar, srv ConnectorConfigServiceServer) {
	// If the following call pancis, it indicates UnimplementedConnectorConfigServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&ConnectorConfigService_ServiceDesc, srv)
}

func _ConnectorConfigService_GetConnectorConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetConnectorConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ConnectorConfigServiceServer).GetConnectorConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ConnectorConfigService_GetConnectorConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ConnectorConfigServiceServer).GetConnectorConfig(ctx, req.(*GetConnectorConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ConnectorConfigService_ServiceDesc is the grpc.ServiceDesc for ConnectorConfigService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ConnectorConfigService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "c1.connectorapi.baton.v1.ConnectorConfigService",
	HandlerType: (*ConnectorConfigServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetConnectorConfig",
			Handler:    _ConnectorConfigService_GetConnectorConfig_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "c1/connectorapi/baton/v1/config.proto",
}
