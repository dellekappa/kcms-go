// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.12
// source: proto/cl.proto

package cl_go_proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type CLCredDefParams struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Attrs []string `protobuf:"bytes,1,rep,name=attrs,proto3" json:"attrs,omitempty"`
}

func (x *CLCredDefParams) Reset() {
	*x = CLCredDefParams{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_cl_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CLCredDefParams) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CLCredDefParams) ProtoMessage() {}

func (x *CLCredDefParams) ProtoReflect() protoreflect.Message {
	mi := &file_proto_cl_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CLCredDefParams.ProtoReflect.Descriptor instead.
func (*CLCredDefParams) Descriptor() ([]byte, []int) {
	return file_proto_cl_proto_rawDescGZIP(), []int{0}
}

func (x *CLCredDefParams) GetAttrs() []string {
	if x != nil {
		return x.Attrs
	}
	return nil
}

type CLCredDefPublicKey struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version             uint32           `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	KeyValue            []byte           `protobuf:"bytes,2,opt,name=key_value,json=keyValue,proto3" json:"key_value,omitempty"`
	KeyCorrectnessProof []byte           `protobuf:"bytes,3,opt,name=key_correctness_proof,json=keyCorrectnessProof,proto3" json:"key_correctness_proof,omitempty"`
	Params              *CLCredDefParams `protobuf:"bytes,4,opt,name=params,proto3" json:"params,omitempty"`
}

func (x *CLCredDefPublicKey) Reset() {
	*x = CLCredDefPublicKey{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_cl_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CLCredDefPublicKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CLCredDefPublicKey) ProtoMessage() {}

func (x *CLCredDefPublicKey) ProtoReflect() protoreflect.Message {
	mi := &file_proto_cl_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CLCredDefPublicKey.ProtoReflect.Descriptor instead.
func (*CLCredDefPublicKey) Descriptor() ([]byte, []int) {
	return file_proto_cl_proto_rawDescGZIP(), []int{1}
}

func (x *CLCredDefPublicKey) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *CLCredDefPublicKey) GetKeyValue() []byte {
	if x != nil {
		return x.KeyValue
	}
	return nil
}

func (x *CLCredDefPublicKey) GetKeyCorrectnessProof() []byte {
	if x != nil {
		return x.KeyCorrectnessProof
	}
	return nil
}

func (x *CLCredDefPublicKey) GetParams() *CLCredDefParams {
	if x != nil {
		return x.Params
	}
	return nil
}

type CLCredDefPrivateKey struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version   uint32              `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	PublicKey *CLCredDefPublicKey `protobuf:"bytes,2,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	KeyValue  []byte              `protobuf:"bytes,3,opt,name=key_value,json=keyValue,proto3" json:"key_value,omitempty"`
}

func (x *CLCredDefPrivateKey) Reset() {
	*x = CLCredDefPrivateKey{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_cl_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CLCredDefPrivateKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CLCredDefPrivateKey) ProtoMessage() {}

func (x *CLCredDefPrivateKey) ProtoReflect() protoreflect.Message {
	mi := &file_proto_cl_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CLCredDefPrivateKey.ProtoReflect.Descriptor instead.
func (*CLCredDefPrivateKey) Descriptor() ([]byte, []int) {
	return file_proto_cl_proto_rawDescGZIP(), []int{2}
}

func (x *CLCredDefPrivateKey) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *CLCredDefPrivateKey) GetPublicKey() *CLCredDefPublicKey {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *CLCredDefPrivateKey) GetKeyValue() []byte {
	if x != nil {
		return x.KeyValue
	}
	return nil
}

type CLCredDefKeyFormat struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Params *CLCredDefParams `protobuf:"bytes,1,opt,name=params,proto3" json:"params,omitempty"`
}

func (x *CLCredDefKeyFormat) Reset() {
	*x = CLCredDefKeyFormat{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_cl_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CLCredDefKeyFormat) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CLCredDefKeyFormat) ProtoMessage() {}

func (x *CLCredDefKeyFormat) ProtoReflect() protoreflect.Message {
	mi := &file_proto_cl_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CLCredDefKeyFormat.ProtoReflect.Descriptor instead.
func (*CLCredDefKeyFormat) Descriptor() ([]byte, []int) {
	return file_proto_cl_proto_rawDescGZIP(), []int{3}
}

func (x *CLCredDefKeyFormat) GetParams() *CLCredDefParams {
	if x != nil {
		return x.Params
	}
	return nil
}

type CLMasterSecret struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version  uint32 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	KeyValue []byte `protobuf:"bytes,2,opt,name=key_value,json=keyValue,proto3" json:"key_value,omitempty"`
}

func (x *CLMasterSecret) Reset() {
	*x = CLMasterSecret{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_cl_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CLMasterSecret) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CLMasterSecret) ProtoMessage() {}

func (x *CLMasterSecret) ProtoReflect() protoreflect.Message {
	mi := &file_proto_cl_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CLMasterSecret.ProtoReflect.Descriptor instead.
func (*CLMasterSecret) Descriptor() ([]byte, []int) {
	return file_proto_cl_proto_rawDescGZIP(), []int{4}
}

func (x *CLMasterSecret) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *CLMasterSecret) GetKeyValue() []byte {
	if x != nil {
		return x.KeyValue
	}
	return nil
}

type CLMasterSecretKeyFormat struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *CLMasterSecretKeyFormat) Reset() {
	*x = CLMasterSecretKeyFormat{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_cl_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CLMasterSecretKeyFormat) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CLMasterSecretKeyFormat) ProtoMessage() {}

func (x *CLMasterSecretKeyFormat) ProtoReflect() protoreflect.Message {
	mi := &file_proto_cl_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CLMasterSecretKeyFormat.ProtoReflect.Descriptor instead.
func (*CLMasterSecretKeyFormat) Descriptor() ([]byte, []int) {
	return file_proto_cl_proto_rawDescGZIP(), []int{5}
}

var File_proto_cl_proto protoreflect.FileDescriptor

var file_proto_cl_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x12, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e,
	0x74, 0x69, 0x6e, 0x6b, 0x22, 0x27, 0x0a, 0x0f, 0x43, 0x4c, 0x43, 0x72, 0x65, 0x64, 0x44, 0x65,
	0x66, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x74, 0x74, 0x72, 0x73,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x05, 0x61, 0x74, 0x74, 0x72, 0x73, 0x22, 0xbc, 0x01,
	0x0a, 0x12, 0x43, 0x4c, 0x43, 0x72, 0x65, 0x64, 0x44, 0x65, 0x66, 0x50, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x4b, 0x65, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1b,
	0x0a, 0x09, 0x6b, 0x65, 0x79, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x08, 0x6b, 0x65, 0x79, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x32, 0x0a, 0x15, 0x6b,
	0x65, 0x79, 0x5f, 0x63, 0x6f, 0x72, 0x72, 0x65, 0x63, 0x74, 0x6e, 0x65, 0x73, 0x73, 0x5f, 0x70,
	0x72, 0x6f, 0x6f, 0x66, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x13, 0x6b, 0x65, 0x79, 0x43,
	0x6f, 0x72, 0x72, 0x65, 0x63, 0x74, 0x6e, 0x65, 0x73, 0x73, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12,
	0x3b, 0x0a, 0x06, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x23, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e,
	0x74, 0x69, 0x6e, 0x6b, 0x2e, 0x43, 0x4c, 0x43, 0x72, 0x65, 0x64, 0x44, 0x65, 0x66, 0x50, 0x61,
	0x72, 0x61, 0x6d, 0x73, 0x52, 0x06, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x22, 0x93, 0x01, 0x0a,
	0x13, 0x43, 0x4c, 0x43, 0x72, 0x65, 0x64, 0x44, 0x65, 0x66, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74,
	0x65, 0x4b, 0x65, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x45,
	0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x26, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x6f, 0x2e, 0x74, 0x69, 0x6e, 0x6b, 0x2e, 0x43, 0x4c, 0x43, 0x72, 0x65, 0x64, 0x44, 0x65,
	0x66, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x1b, 0x0a, 0x09, 0x6b, 0x65, 0x79, 0x5f, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x6b, 0x65, 0x79, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x22, 0x51, 0x0a, 0x12, 0x43, 0x4c, 0x43, 0x72, 0x65, 0x64, 0x44, 0x65, 0x66, 0x4b,
	0x65, 0x79, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x12, 0x3b, 0x0a, 0x06, 0x70, 0x61, 0x72, 0x61,
	0x6d, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x74, 0x69, 0x6e, 0x6b, 0x2e, 0x43, 0x4c,
	0x43, 0x72, 0x65, 0x64, 0x44, 0x65, 0x66, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x52, 0x06, 0x70,
	0x61, 0x72, 0x61, 0x6d, 0x73, 0x22, 0x47, 0x0a, 0x0e, 0x43, 0x4c, 0x4d, 0x61, 0x73, 0x74, 0x65,
	0x72, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x12, 0x1b, 0x0a, 0x09, 0x6b, 0x65, 0x79, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x6b, 0x65, 0x79, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x19,
	0x0a, 0x17, 0x43, 0x4c, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x4b, 0x65, 0x79, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x42, 0x4b, 0x5a, 0x49, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74, 0x72, 0x75, 0x73, 0x74, 0x62, 0x6c, 0x6f,
	0x63, 0x2f, 0x6b, 0x6d, 0x73, 0x2d, 0x67, 0x6f, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f,
	0x74, 0x69, 0x6e, 0x6b, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x70, 0x72, 0x69, 0x6d, 0x69,
	0x74, 0x69, 0x76, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6c, 0x5f, 0x67, 0x6f,
	0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_cl_proto_rawDescOnce sync.Once
	file_proto_cl_proto_rawDescData = file_proto_cl_proto_rawDesc
)

func file_proto_cl_proto_rawDescGZIP() []byte {
	file_proto_cl_proto_rawDescOnce.Do(func() {
		file_proto_cl_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_cl_proto_rawDescData)
	})
	return file_proto_cl_proto_rawDescData
}

var file_proto_cl_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_proto_cl_proto_goTypes = []interface{}{
	(*CLCredDefParams)(nil),         // 0: google.crypto.tink.CLCredDefParams
	(*CLCredDefPublicKey)(nil),      // 1: google.crypto.tink.CLCredDefPublicKey
	(*CLCredDefPrivateKey)(nil),     // 2: google.crypto.tink.CLCredDefPrivateKey
	(*CLCredDefKeyFormat)(nil),      // 3: google.crypto.tink.CLCredDefKeyFormat
	(*CLMasterSecret)(nil),          // 4: google.crypto.tink.CLMasterSecret
	(*CLMasterSecretKeyFormat)(nil), // 5: google.crypto.tink.CLMasterSecretKeyFormat
}
var file_proto_cl_proto_depIdxs = []int32{
	0, // 0: google.crypto.tink.CLCredDefPublicKey.params:type_name -> google.crypto.tink.CLCredDefParams
	1, // 1: google.crypto.tink.CLCredDefPrivateKey.public_key:type_name -> google.crypto.tink.CLCredDefPublicKey
	0, // 2: google.crypto.tink.CLCredDefKeyFormat.params:type_name -> google.crypto.tink.CLCredDefParams
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_proto_cl_proto_init() }
func file_proto_cl_proto_init() {
	if File_proto_cl_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_cl_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CLCredDefParams); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_cl_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CLCredDefPublicKey); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_cl_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CLCredDefPrivateKey); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_cl_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CLCredDefKeyFormat); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_cl_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CLMasterSecret); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_cl_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CLMasterSecretKeyFormat); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_cl_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_cl_proto_goTypes,
		DependencyIndexes: file_proto_cl_proto_depIdxs,
		MessageInfos:      file_proto_cl_proto_msgTypes,
	}.Build()
	File_proto_cl_proto = out.File
	file_proto_cl_proto_rawDesc = nil
	file_proto_cl_proto_goTypes = nil
	file_proto_cl_proto_depIdxs = nil
}
