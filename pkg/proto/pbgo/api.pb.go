// Code generated by protoc-gen-go. DO NOT EDIT.
// source: datadog/api/v1/api.proto

package pbgo

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

func init() { proto.RegisterFile("datadog/api/v1/api.proto", fileDescriptor_34b6b7230a30f878) }

var fileDescriptor_34b6b7230a30f878 = []byte{
	// 451 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x93, 0x31, 0x6f, 0x13, 0x31,
	0x18, 0x86, 0x75, 0x48, 0x65, 0x70, 0x45, 0x29, 0x16, 0x08, 0x14, 0xa5, 0x2a, 0x35, 0xad, 0x52,
	0x05, 0x11, 0x93, 0xb2, 0x75, 0x83, 0x00, 0x65, 0x26, 0x99, 0x58, 0x90, 0x7b, 0xf7, 0xd5, 0x39,
	0x91, 0xd8, 0xae, 0xfd, 0x25, 0x52, 0x56, 0x36, 0x24, 0xa4, 0x0e, 0x8c, 0xfc, 0x2c, 0xfe, 0x02,
	0x13, 0xbf, 0x02, 0xd9, 0x3e, 0x9f, 0x2e, 0xbd, 0x36, 0x9d, 0x6c, 0xe7, 0x7d, 0xac, 0xf7, 0x91,
	0x73, 0x1f, 0x79, 0x56, 0x08, 0x14, 0x85, 0x96, 0x5c, 0x98, 0x92, 0x2f, 0x87, 0x7e, 0x19, 0x18,
	0xab, 0x51, 0xd3, 0x9d, 0x2a, 0x19, 0xf8, 0x9f, 0x96, 0xc3, 0x4e, 0x37, 0x91, 0x73, 0x5d, 0xc0,
	0xcc, 0xb3, 0x61, 0x13, 0xe9, 0x4e, 0x2f, 0xa5, 0x16, 0xe6, 0x1a, 0x21, 0xd7, 0xea, 0xa2, 0x5c,
	0x3f, 0x54, 0x60, 0x57, 0x6a, 0x2d, 0x67, 0x10, 0xfa, 0x84, 0x52, 0x1a, 0x05, 0x96, 0x5a, 0xb9,
	0x98, 0x9e, 0x5c, 0x92, 0xad, 0xb7, 0x12, 0x14, 0xd2, 0x29, 0xd9, 0x3e, 0x03, 0xfc, 0xa4, 0x1d,
	0x2a, 0x31, 0x07, 0x7a, 0x30, 0x48, 0x36, 0xb1, 0x74, 0x39, 0x1c, 0xa4, 0xec, 0x33, 0x5c, 0x2e,
	0xc0, 0x61, 0x67, 0x7f, 0x13, 0x62, 0x66, 0x2b, 0xf6, 0xe4, 0xfb, 0x9f, 0xbf, 0xbf, 0xee, 0x3d,
	0xa4, 0x0f, 0xbc, 0xbb, 0xb4, 0x26, 0xe7, 0x53, 0xed, 0xf0, 0xe4, 0xdf, 0x16, 0xd9, 0x0e, 0x9d,
	0x63, 0xc8, 0x17, 0x16, 0xe8, 0x55, 0x46, 0x1e, 0x4f, 0x84, 0x94, 0x60, 0xc7, 0x68, 0x41, 0xcc,
	0x3f, 0x28, 0x2c, 0xb1, 0x04, 0x47, 0x5f, 0xb4, 0x0b, 0x22, 0x31, 0x11, 0xd2, 0x25, 0x8b, 0xc3,
	0xcd, 0x90, 0x33, 0x5a, 0x39, 0x60, 0xfd, 0xa0, 0x72, 0xc8, 0xf6, 0x6b, 0x15, 0x0c, 0x8d, 0xdc,
	0x05, 0xf6, 0x2b, 0x54, 0x9d, 0xa7, 0x59, 0xff, 0x75, 0x46, 0x7f, 0x64, 0xe4, 0x51, 0x34, 0xfa,
	0x08, 0x98, 0x4f, 0x83, 0xd0, 0x8a, 0xde, 0xd0, 0xd4, 0x88, 0x93, 0xcf, 0xd1, 0x1d, 0x54, 0x25,
	0xd4, 0x0b, 0x42, 0x07, 0xac, 0x7b, 0x5d, 0xe8, 0xc2, 0xc3, 0xd1, 0x67, 0x75, 0x9a, 0xf5, 0xe9,
	0xef, 0x8c, 0x3c, 0x7d, 0xaf, 0xa5, 0x43, 0x81, 0xae, 0x18, 0x09, 0x83, 0x0b, 0x0b, 0x13, 0x5b,
	0x7a, 0x96, 0xf6, 0xda, 0x5d, 0xeb, 0x44, 0x92, 0x3a, 0xbe, 0x1b, 0xac, 0xbc, 0x5e, 0x05, 0xaf,
	0x1e, 0x63, 0xb5, 0x57, 0x91, 0xca, 0x79, 0x1e, 0xaf, 0x70, 0x8c, 0x77, 0xbc, 0xdd, 0xcf, 0xa6,
	0xdd, 0x18, 0x30, 0xfd, 0x8f, 0x02, 0x81, 0xee, 0xb5, 0x4b, 0x1b, 0xf1, 0x4d, 0x0f, 0xd5, 0x88,
	0x6b, 0xa1, 0x97, 0x41, 0xe8, 0x88, 0x3d, 0xdf, 0x20, 0xe4, 0x8f, 0xe0, 0x75, 0xae, 0x32, 0xb2,
	0x3b, 0x9a, 0x95, 0xa0, 0xf0, 0x0c, 0x70, 0x14, 0xa6, 0xc0, 0x35, 0x5e, 0xa9, 0x9a, 0x8b, 0xeb,
	0x44, 0xfb, 0x95, 0x6e, 0x05, 0x2b, 0xa9, 0xe3, 0x20, 0xc5, 0xd8, 0x5e, 0x2d, 0xb5, 0x36, 0x85,
	0x71, 0xf1, 0x1f, 0xd3, 0xbb, 0xdd, 0x2f, 0x3b, 0xe6, 0x9b, 0xe4, 0x61, 0xd8, 0xb8, 0x39, 0x97,
	0xfa, 0xfc, 0x7e, 0xd8, 0xbf, 0xf9, 0x1f, 0x00, 0x00, 0xff, 0xff, 0x6d, 0xe7, 0xaa, 0x42, 0x09,
	0x04, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// AgentClient is the client API for Agent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AgentClient interface {
	// get the hostname
	GetHostname(ctx context.Context, in *HostnameRequest, opts ...grpc.CallOption) (*HostnameReply, error)
}

type agentClient struct {
	cc *grpc.ClientConn
}

func NewAgentClient(cc *grpc.ClientConn) AgentClient {
	return &agentClient{cc}
}

func (c *agentClient) GetHostname(ctx context.Context, in *HostnameRequest, opts ...grpc.CallOption) (*HostnameReply, error) {
	out := new(HostnameReply)
	err := c.cc.Invoke(ctx, "/datadog.api.v1.Agent/GetHostname", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AgentServer is the server API for Agent service.
type AgentServer interface {
	// get the hostname
	GetHostname(context.Context, *HostnameRequest) (*HostnameReply, error)
}

// UnimplementedAgentServer can be embedded to have forward compatible implementations.
type UnimplementedAgentServer struct {
}

func (*UnimplementedAgentServer) GetHostname(ctx context.Context, req *HostnameRequest) (*HostnameReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetHostname not implemented")
}

func RegisterAgentServer(s *grpc.Server, srv AgentServer) {
	s.RegisterService(&_Agent_serviceDesc, srv)
}

func _Agent_GetHostname_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HostnameRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentServer).GetHostname(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datadog.api.v1.Agent/GetHostname",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AgentServer).GetHostname(ctx, req.(*HostnameRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Agent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "datadog.api.v1.Agent",
	HandlerType: (*AgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetHostname",
			Handler:    _Agent_GetHostname_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "datadog/api/v1/api.proto",
}

// AgentSecureClient is the client API for AgentSecure service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AgentSecureClient interface {
	// subscribes to added, removed, or changed entities in the Tagger
	// and streams them to clients as events.
	// can be called through the HTTP gateway, and events will be streamed as JSON:
	//   $  curl -H "authorization: Bearer $(cat /etc/datadog-agent/auth_token)" \
	//      -XPOST -k https://localhost:5001/v1/grpc/tagger/stream_entities
	//   {
	//    "result": {
	//        "entity": {
	//            "id": {
	//                "prefix": "kubernetes_pod_uid",
	//                "uid": "4025461f832caf3fceb7fc2a32f879c6"
	//            },
	//            "hash": "cad4fc8fc409fcc1",
	//            "lowCardinalityTags": [
	//                "kube_namespace:kube-system",
	//                "pod_phase:running"
	//            ]
	//        }
	//    }
	//}
	TaggerStreamEntities(ctx context.Context, in *StreamTagsRequest, opts ...grpc.CallOption) (AgentSecure_TaggerStreamEntitiesClient, error)
	// fetches an entity from the Tagger with the desired cardinality tags.
	// can be called through the HTTP gateway, and entity will be returned as JSON:
	//   $ curl -H "authorization: Bearer $(cat /etc/datadog-agent/auth_token)" \
	//      -XPOST -k -H "Content-Type: application/json" \
	//      --data '{"id":{"prefix":"kubernetes_pod_uid","uid":"d575fb58-82dc-418e-bfb1-aececc9bc507"}}' \
	//      https://localhost:5001/v1/grpc/tagger/fetch_entity
	//   {
	//    "id": {
	//        "prefix": "kubernetes_pod_uid",
	//        "uid": "d575fb58-82dc-418e-bfb1-aececc9bc507"
	//    },
	//    "tags": [
	//        "kube_namespace:kube-system",
	//        "pod_phase:running",
	//        "kube_deployment:coredns",
	//        "kube_service:kube-dns"
	//    ]
	//}
	TaggerFetchEntity(ctx context.Context, in *FetchEntityRequest, opts ...grpc.CallOption) (*FetchEntityResponse, error)
	// Trigger a dogstatsd capture. Only one capture can be triggered at a time.
	// Can be called through the HTTP gateway, and entity will be returned as JSON:
	//      TODO: add the curl code here
	DogstatsdCaptureTrigger(ctx context.Context, in *CaptureTriggerRequest, opts ...grpc.CallOption) (*CaptureTriggerResponse, error)
	// Trigger a dogstatsd capture. Only one capture can be triggered at a time.
	// Can be called through the HTTP gateway, and entity will be returned as JSON:
	//      TODO: add the curl code here
	DogstatsdSetTaggerState(ctx context.Context, in *TaggerState, opts ...grpc.CallOption) (*TaggerStateResponse, error)
	ClientGetConfigs(ctx context.Context, in *ClientGetConfigsRequest, opts ...grpc.CallOption) (*ClientGetConfigsResponse, error)
}

type agentSecureClient struct {
	cc *grpc.ClientConn
}

func NewAgentSecureClient(cc *grpc.ClientConn) AgentSecureClient {
	return &agentSecureClient{cc}
}

func (c *agentSecureClient) TaggerStreamEntities(ctx context.Context, in *StreamTagsRequest, opts ...grpc.CallOption) (AgentSecure_TaggerStreamEntitiesClient, error) {
	stream, err := c.cc.NewStream(ctx, &_AgentSecure_serviceDesc.Streams[0], "/datadog.api.v1.AgentSecure/TaggerStreamEntities", opts...)
	if err != nil {
		return nil, err
	}
	x := &agentSecureTaggerStreamEntitiesClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type AgentSecure_TaggerStreamEntitiesClient interface {
	Recv() (*StreamTagsResponse, error)
	grpc.ClientStream
}

type agentSecureTaggerStreamEntitiesClient struct {
	grpc.ClientStream
}

func (x *agentSecureTaggerStreamEntitiesClient) Recv() (*StreamTagsResponse, error) {
	m := new(StreamTagsResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *agentSecureClient) TaggerFetchEntity(ctx context.Context, in *FetchEntityRequest, opts ...grpc.CallOption) (*FetchEntityResponse, error) {
	out := new(FetchEntityResponse)
	err := c.cc.Invoke(ctx, "/datadog.api.v1.AgentSecure/TaggerFetchEntity", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *agentSecureClient) DogstatsdCaptureTrigger(ctx context.Context, in *CaptureTriggerRequest, opts ...grpc.CallOption) (*CaptureTriggerResponse, error) {
	out := new(CaptureTriggerResponse)
	err := c.cc.Invoke(ctx, "/datadog.api.v1.AgentSecure/DogstatsdCaptureTrigger", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *agentSecureClient) DogstatsdSetTaggerState(ctx context.Context, in *TaggerState, opts ...grpc.CallOption) (*TaggerStateResponse, error) {
	out := new(TaggerStateResponse)
	err := c.cc.Invoke(ctx, "/datadog.api.v1.AgentSecure/DogstatsdSetTaggerState", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *agentSecureClient) ClientGetConfigs(ctx context.Context, in *ClientGetConfigsRequest, opts ...grpc.CallOption) (*ClientGetConfigsResponse, error) {
	out := new(ClientGetConfigsResponse)
	err := c.cc.Invoke(ctx, "/datadog.api.v1.AgentSecure/ClientGetConfigs", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AgentSecureServer is the server API for AgentSecure service.
type AgentSecureServer interface {
	// subscribes to added, removed, or changed entities in the Tagger
	// and streams them to clients as events.
	// can be called through the HTTP gateway, and events will be streamed as JSON:
	//   $  curl -H "authorization: Bearer $(cat /etc/datadog-agent/auth_token)" \
	//      -XPOST -k https://localhost:5001/v1/grpc/tagger/stream_entities
	//   {
	//    "result": {
	//        "entity": {
	//            "id": {
	//                "prefix": "kubernetes_pod_uid",
	//                "uid": "4025461f832caf3fceb7fc2a32f879c6"
	//            },
	//            "hash": "cad4fc8fc409fcc1",
	//            "lowCardinalityTags": [
	//                "kube_namespace:kube-system",
	//                "pod_phase:running"
	//            ]
	//        }
	//    }
	//}
	TaggerStreamEntities(*StreamTagsRequest, AgentSecure_TaggerStreamEntitiesServer) error
	// fetches an entity from the Tagger with the desired cardinality tags.
	// can be called through the HTTP gateway, and entity will be returned as JSON:
	//   $ curl -H "authorization: Bearer $(cat /etc/datadog-agent/auth_token)" \
	//      -XPOST -k -H "Content-Type: application/json" \
	//      --data '{"id":{"prefix":"kubernetes_pod_uid","uid":"d575fb58-82dc-418e-bfb1-aececc9bc507"}}' \
	//      https://localhost:5001/v1/grpc/tagger/fetch_entity
	//   {
	//    "id": {
	//        "prefix": "kubernetes_pod_uid",
	//        "uid": "d575fb58-82dc-418e-bfb1-aececc9bc507"
	//    },
	//    "tags": [
	//        "kube_namespace:kube-system",
	//        "pod_phase:running",
	//        "kube_deployment:coredns",
	//        "kube_service:kube-dns"
	//    ]
	//}
	TaggerFetchEntity(context.Context, *FetchEntityRequest) (*FetchEntityResponse, error)
	// Trigger a dogstatsd capture. Only one capture can be triggered at a time.
	// Can be called through the HTTP gateway, and entity will be returned as JSON:
	//      TODO: add the curl code here
	DogstatsdCaptureTrigger(context.Context, *CaptureTriggerRequest) (*CaptureTriggerResponse, error)
	// Trigger a dogstatsd capture. Only one capture can be triggered at a time.
	// Can be called through the HTTP gateway, and entity will be returned as JSON:
	//      TODO: add the curl code here
	DogstatsdSetTaggerState(context.Context, *TaggerState) (*TaggerStateResponse, error)
	ClientGetConfigs(context.Context, *ClientGetConfigsRequest) (*ClientGetConfigsResponse, error)
}

// UnimplementedAgentSecureServer can be embedded to have forward compatible implementations.
type UnimplementedAgentSecureServer struct {
}

func (*UnimplementedAgentSecureServer) TaggerStreamEntities(req *StreamTagsRequest, srv AgentSecure_TaggerStreamEntitiesServer) error {
	return status.Errorf(codes.Unimplemented, "method TaggerStreamEntities not implemented")
}
func (*UnimplementedAgentSecureServer) TaggerFetchEntity(ctx context.Context, req *FetchEntityRequest) (*FetchEntityResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TaggerFetchEntity not implemented")
}
func (*UnimplementedAgentSecureServer) DogstatsdCaptureTrigger(ctx context.Context, req *CaptureTriggerRequest) (*CaptureTriggerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DogstatsdCaptureTrigger not implemented")
}
func (*UnimplementedAgentSecureServer) DogstatsdSetTaggerState(ctx context.Context, req *TaggerState) (*TaggerStateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DogstatsdSetTaggerState not implemented")
}
func (*UnimplementedAgentSecureServer) ClientGetConfigs(ctx context.Context, req *ClientGetConfigsRequest) (*ClientGetConfigsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ClientGetConfigs not implemented")
}

func RegisterAgentSecureServer(s *grpc.Server, srv AgentSecureServer) {
	s.RegisterService(&_AgentSecure_serviceDesc, srv)
}

func _AgentSecure_TaggerStreamEntities_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(StreamTagsRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(AgentSecureServer).TaggerStreamEntities(m, &agentSecureTaggerStreamEntitiesServer{stream})
}

type AgentSecure_TaggerStreamEntitiesServer interface {
	Send(*StreamTagsResponse) error
	grpc.ServerStream
}

type agentSecureTaggerStreamEntitiesServer struct {
	grpc.ServerStream
}

func (x *agentSecureTaggerStreamEntitiesServer) Send(m *StreamTagsResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _AgentSecure_TaggerFetchEntity_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FetchEntityRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentSecureServer).TaggerFetchEntity(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datadog.api.v1.AgentSecure/TaggerFetchEntity",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AgentSecureServer).TaggerFetchEntity(ctx, req.(*FetchEntityRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AgentSecure_DogstatsdCaptureTrigger_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CaptureTriggerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentSecureServer).DogstatsdCaptureTrigger(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datadog.api.v1.AgentSecure/DogstatsdCaptureTrigger",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AgentSecureServer).DogstatsdCaptureTrigger(ctx, req.(*CaptureTriggerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AgentSecure_DogstatsdSetTaggerState_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TaggerState)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentSecureServer).DogstatsdSetTaggerState(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datadog.api.v1.AgentSecure/DogstatsdSetTaggerState",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AgentSecureServer).DogstatsdSetTaggerState(ctx, req.(*TaggerState))
	}
	return interceptor(ctx, in, info, handler)
}

func _AgentSecure_ClientGetConfigs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ClientGetConfigsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AgentSecureServer).ClientGetConfigs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/datadog.api.v1.AgentSecure/ClientGetConfigs",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AgentSecureServer).ClientGetConfigs(ctx, req.(*ClientGetConfigsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _AgentSecure_serviceDesc = grpc.ServiceDesc{
	ServiceName: "datadog.api.v1.AgentSecure",
	HandlerType: (*AgentSecureServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "TaggerFetchEntity",
			Handler:    _AgentSecure_TaggerFetchEntity_Handler,
		},
		{
			MethodName: "DogstatsdCaptureTrigger",
			Handler:    _AgentSecure_DogstatsdCaptureTrigger_Handler,
		},
		{
			MethodName: "DogstatsdSetTaggerState",
			Handler:    _AgentSecure_DogstatsdSetTaggerState_Handler,
		},
		{
			MethodName: "ClientGetConfigs",
			Handler:    _AgentSecure_ClientGetConfigs_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "TaggerStreamEntities",
			Handler:       _AgentSecure_TaggerStreamEntities_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "datadog/api/v1/api.proto",
}
