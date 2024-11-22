// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.12
// source: proto/aes_cbc_hmac_aead.proto

package aes_cbc_hmac_aead_go_proto

import (
	aes_cbc_go_proto "github.com/dellekappa/kcms-go/crypto/tinkcrypto/primitive/proto/aes_cbc_go_proto"
	hmac_go_proto "github.com/tink-crypto/tink-go/v2/proto/hmac_go
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

type AesCbcHmacAeadKeyFormat struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AesCbcKeyFormat *aes_cbc_go_proto.AesCbcKeyFormat `protobuf:"bytes,1,opt,name=aes_cbc_key_format,json=aesCbcKeyFormat,proto3" json:"aes_cbc_key_format,omitempty"`
	HmacKeyFormat   *hmac_go_proto.HmacKeyFormat      `protobuf:"bytes,2,opt,name=hmac_key_format,json=hmacKeyFormat,proto3" json:"hmac_key_format,omitempty"`
}

func (x *AesCbcHmacAeadKeyFormat) Reset() {
	*x = AesCbcHmacAeadKeyFormat{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_aes_cbc_hmac_aead_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AesCbcHmacAeadKeyFormat) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AesCbcHmacAeadKeyFormat) ProtoMessage() {}

func (x *AesCbcHmacAeadKeyFormat) ProtoReflect() protoreflect.Message {
	mi := &file_proto_aes_cbc_hmac_aead_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AesCbcHmacAeadKeyFormat.ProtoReflect.Descriptor instead.
func (*AesCbcHmacAeadKeyFormat) Descriptor() ([]byte, []int) {
	return file_proto_aes_cbc_hmac_aead_proto_rawDescGZIP(), []int{0}
}

func (x *AesCbcHmacAeadKeyFormat) GetAesCbcKeyFormat() *aes_cbc_go_proto.AesCbcKeyFormat {
	if x != nil {
		return x.AesCbcKeyFormat
	}
	return nil
}

func (x *AesCbcHmacAeadKeyFormat) GetHmacKeyFormat() *hmac_go_proto.HmacKeyFormat {
	if x != nil {
		return x.HmacKeyFormat
	}
	return nil
}

type AesCbcHmacAeadKey struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version   uint32                      `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	AesCbcKey *aes_cbc_go_proto.AesCbcKey `protobuf:"bytes,2,opt,name=aes_cbc_key,json=aesCbcKey,proto3" json:"aes_cbc_key,omitempty"`
	HmacKey   *hmac_go_proto.HmacKey      `protobuf:"bytes,3,opt,name=hmac_key,json=hmacKey,proto3" json:"hmac_key,omitempty"`
}

func (x *AesCbcHmacAeadKey) Reset() {
	*x = AesCbcHmacAeadKey{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_aes_cbc_hmac_aead_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AesCbcHmacAeadKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AesCbcHmacAeadKey) ProtoMessage() {}

func (x *AesCbcHmacAeadKey) ProtoReflect() protoreflect.Message {
	mi := &file_proto_aes_cbc_hmac_aead_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AesCbcHmacAeadKey.ProtoReflect.Descriptor instead.
func (*AesCbcHmacAeadKey) Descriptor() ([]byte, []int) {
	return file_proto_aes_cbc_hmac_aead_proto_rawDescGZIP(), []int{1}
}

func (x *AesCbcHmacAeadKey) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *AesCbcHmacAeadKey) GetAesCbcKey() *aes_cbc_go_proto.AesCbcKey {
	if x != nil {
		return x.AesCbcKey
	}
	return nil
}

func (x *AesCbcHmacAeadKey) GetHmacKey() *hmac_go_proto.HmacKey {
	if x != nil {
		return x.HmacKey
	}
	return nil
}

var File_proto_aes_cbc_hmac_aead_proto protoreflect.FileDescriptor

var file_proto_aes_cbc_hmac_aead_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x61, 0x65, 0x73, 0x5f, 0x63, 0x62, 0x63, 0x5f,
	0x68, 0x6d, 0x61, 0x63, 0x5f, 0x61, 0x65, 0x61, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x12, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x74,
	0x69, 0x6e, 0x6b, 0x1a, 0x13, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x61, 0x65, 0x73, 0x5f, 0x63,
	0x62, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x10, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x68, 0x6d, 0x61, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb6, 0x01, 0x0a, 0x17, 0x41,
	0x65, 0x73, 0x43, 0x62, 0x63, 0x48, 0x6d, 0x61, 0x63, 0x41, 0x65, 0x61, 0x64, 0x4b, 0x65, 0x79,
	0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x12, 0x50, 0x0a, 0x12, 0x61, 0x65, 0x73, 0x5f, 0x63, 0x62,
	0x63, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x23, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x6f, 0x2e, 0x74, 0x69, 0x6e, 0x6b, 0x2e, 0x41, 0x65, 0x73, 0x43, 0x62, 0x63, 0x4b, 0x65,
	0x79, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x52, 0x0f, 0x61, 0x65, 0x73, 0x43, 0x62, 0x63, 0x4b,
	0x65, 0x79, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x12, 0x49, 0x0a, 0x0f, 0x68, 0x6d, 0x61, 0x63,
	0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x21, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x6f, 0x2e, 0x74, 0x69, 0x6e, 0x6b, 0x2e, 0x48, 0x6d, 0x61, 0x63, 0x4b, 0x65, 0x79, 0x46, 0x6f,
	0x72, 0x6d, 0x61, 0x74, 0x52, 0x0d, 0x68, 0x6d, 0x61, 0x63, 0x4b, 0x65, 0x79, 0x46, 0x6f, 0x72,
	0x6d, 0x61, 0x74, 0x22, 0xa4, 0x01, 0x0a, 0x11, 0x41, 0x65, 0x73, 0x43, 0x62, 0x63, 0x48, 0x6d,
	0x61, 0x63, 0x41, 0x65, 0x61, 0x64, 0x4b, 0x65, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x12, 0x3d, 0x0a, 0x0b, 0x61, 0x65, 0x73, 0x5f, 0x63, 0x62, 0x63, 0x5f, 0x6b,
	0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x74, 0x69, 0x6e, 0x6b, 0x2e, 0x41, 0x65,
	0x73, 0x43, 0x62, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x09, 0x61, 0x65, 0x73, 0x43, 0x62, 0x63, 0x4b,
	0x65, 0x79, 0x12, 0x36, 0x0a, 0x08, 0x68, 0x6d, 0x61, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x72,
	0x79, 0x70, 0x74, 0x6f, 0x2e, 0x74, 0x69, 0x6e, 0x6b, 0x2e, 0x48, 0x6d, 0x61, 0x63, 0x4b, 0x65,
	0x79, 0x52, 0x07, 0x68, 0x6d, 0x61, 0x63, 0x4b, 0x65, 0x79, 0x42, 0x5a, 0x5a, 0x58, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74, 0x72, 0x75, 0x73, 0x74, 0x62, 0x6c,
	0x6f, 0x63, 0x2f, 0x6b, 0x6d, 0x73, 0x2d, 0x67, 0x6f, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f,
	0x2f, 0x74, 0x69, 0x6e, 0x6b, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x70, 0x72, 0x69, 0x6d,
	0x69, 0x74, 0x69, 0x76, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x61, 0x65, 0x73, 0x5f,
	0x63, 0x62, 0x63, 0x5f, 0x68, 0x6d, 0x61, 0x63, 0x5f, 0x61, 0x65, 0x61, 0x64, 0x5f, 0x67, 0x6f,
	0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_aes_cbc_hmac_aead_proto_rawDescOnce sync.Once
	file_proto_aes_cbc_hmac_aead_proto_rawDescData = file_proto_aes_cbc_hmac_aead_proto_rawDesc
)

func file_proto_aes_cbc_hmac_aead_proto_rawDescGZIP() []byte {
	file_proto_aes_cbc_hmac_aead_proto_rawDescOnce.Do(func() {
		file_proto_aes_cbc_hmac_aead_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_aes_cbc_hmac_aead_proto_rawDescData)
	})
	return file_proto_aes_cbc_hmac_aead_proto_rawDescData
}

var file_proto_aes_cbc_hmac_aead_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_proto_aes_cbc_hmac_aead_proto_goTypes = []interface{}{
	(*AesCbcHmacAeadKeyFormat)(nil),          // 0: google.crypto.tink.AesCbcHmacAeadKeyFormat
	(*AesCbcHmacAeadKey)(nil),                // 1: google.crypto.tink.AesCbcHmacAeadKey
	(*aes_cbc_go_proto.AesCbcKeyFormat)(nil), // 2: google.crypto.tink.AesCbcKeyFormat
	(*hmac_go_proto.HmacKeyFormat)(nil),      // 3: google.crypto.tink.HmacKeyFormat
	(*aes_cbc_go_proto.AesCbcKey)(nil),       // 4: google.crypto.tink.AesCbcKey
	(*hmac_go_proto.HmacKey)(nil),            // 5: google.crypto.tink.HmacKey
}
var file_proto_aes_cbc_hmac_aead_proto_depIdxs = []int32{
	2, // 0: google.crypto.tink.AesCbcHmacAeadKeyFormat.aes_cbc_key_format:type_name -> google.crypto.tink.AesCbcKeyFormat
	3, // 1: google.crypto.tink.AesCbcHmacAeadKeyFormat.hmac_key_format:type_name -> google.crypto.tink.HmacKeyFormat
	4, // 2: google.crypto.tink.AesCbcHmacAeadKey.aes_cbc_key:type_name -> google.crypto.tink.AesCbcKey
	5, // 3: google.crypto.tink.AesCbcHmacAeadKey.hmac_key:type_name -> google.crypto.tink.HmacKey
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_proto_aes_cbc_hmac_aead_proto_init() }
func file_proto_aes_cbc_hmac_aead_proto_init() {
	if File_proto_aes_cbc_hmac_aead_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_aes_cbc_hmac_aead_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AesCbcHmacAeadKeyFormat); i {
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
		file_proto_aes_cbc_hmac_aead_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AesCbcHmacAeadKey); i {
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
			RawDescriptor: file_proto_aes_cbc_hmac_aead_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_aes_cbc_hmac_aead_proto_goTypes,
		DependencyIndexes: file_proto_aes_cbc_hmac_aead_proto_depIdxs,
		MessageInfos:      file_proto_aes_cbc_hmac_aead_proto_msgTypes,
	}.Build()
	File_proto_aes_cbc_hmac_aead_proto = out.File
	file_proto_aes_cbc_hmac_aead_proto_rawDesc = nil
	file_proto_aes_cbc_hmac_aead_proto_goTypes = nil
	file_proto_aes_cbc_hmac_aead_proto_depIdxs = nil
}
