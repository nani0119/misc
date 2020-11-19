// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: calc_add.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_calc_5fadd_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_calc_5fadd_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3013000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3013000 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/inlined_string_field.h>
#include <google/protobuf/metadata_lite.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/empty.pb.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_calc_5fadd_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_calc_5fadd_2eproto {
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTableField entries[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::AuxiliaryParseTableField aux[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTable schema[3]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::FieldMetadata field_metadata[];
  static const ::PROTOBUF_NAMESPACE_ID::internal::SerializationTable serialization_table[];
  static const ::PROTOBUF_NAMESPACE_ID::uint32 offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_calc_5fadd_2eproto;
namespace Calculation {
class Addend;
class AddendDefaultTypeInternal;
extern AddendDefaultTypeInternal _Addend_default_instance_;
class Num;
class NumDefaultTypeInternal;
extern NumDefaultTypeInternal _Num_default_instance_;
class Sum;
class SumDefaultTypeInternal;
extern SumDefaultTypeInternal _Sum_default_instance_;
}  // namespace Calculation
PROTOBUF_NAMESPACE_OPEN
template<> ::Calculation::Addend* Arena::CreateMaybeMessage<::Calculation::Addend>(Arena*);
template<> ::Calculation::Num* Arena::CreateMaybeMessage<::Calculation::Num>(Arena*);
template<> ::Calculation::Sum* Arena::CreateMaybeMessage<::Calculation::Sum>(Arena*);
PROTOBUF_NAMESPACE_CLOSE
namespace Calculation {

// ===================================================================

class Num PROTOBUF_FINAL :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:Calculation.Num) */ {
 public:
  inline Num() : Num(nullptr) {}
  virtual ~Num();

  Num(const Num& from);
  Num(Num&& from) noexcept
    : Num() {
    *this = ::std::move(from);
  }

  inline Num& operator=(const Num& from) {
    CopyFrom(from);
    return *this;
  }
  inline Num& operator=(Num&& from) noexcept {
    if (GetArena() == from.GetArena()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return GetMetadataStatic().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return GetMetadataStatic().reflection;
  }
  static const Num& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const Num* internal_default_instance() {
    return reinterpret_cast<const Num*>(
               &_Num_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(Num& a, Num& b) {
    a.Swap(&b);
  }
  inline void Swap(Num* other) {
    if (other == this) return;
    if (GetArena() == other->GetArena()) {
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(Num* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetArena() == other->GetArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline Num* New() const final {
    return CreateMaybeMessage<Num>(nullptr);
  }

  Num* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<Num>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const Num& from);
  void MergeFrom(const Num& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  inline void SharedCtor();
  inline void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(Num* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "Calculation.Num";
  }
  protected:
  explicit Num(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;
  private:
  static ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadataStatic() {
    ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&::descriptor_table_calc_5fadd_2eproto);
    return ::descriptor_table_calc_5fadd_2eproto.file_level_metadata[kIndexInFileMessages];
  }

  public:

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kNumFieldNumber = 1,
  };
  // repeated int32 num = 1;
  int num_size() const;
  private:
  int _internal_num_size() const;
  public:
  void clear_num();
  private:
  ::PROTOBUF_NAMESPACE_ID::int32 _internal_num(int index) const;
  const ::PROTOBUF_NAMESPACE_ID::RepeatedField< ::PROTOBUF_NAMESPACE_ID::int32 >&
      _internal_num() const;
  void _internal_add_num(::PROTOBUF_NAMESPACE_ID::int32 value);
  ::PROTOBUF_NAMESPACE_ID::RepeatedField< ::PROTOBUF_NAMESPACE_ID::int32 >*
      _internal_mutable_num();
  public:
  ::PROTOBUF_NAMESPACE_ID::int32 num(int index) const;
  void set_num(int index, ::PROTOBUF_NAMESPACE_ID::int32 value);
  void add_num(::PROTOBUF_NAMESPACE_ID::int32 value);
  const ::PROTOBUF_NAMESPACE_ID::RepeatedField< ::PROTOBUF_NAMESPACE_ID::int32 >&
      num() const;
  ::PROTOBUF_NAMESPACE_ID::RepeatedField< ::PROTOBUF_NAMESPACE_ID::int32 >*
      mutable_num();

  // @@protoc_insertion_point(class_scope:Calculation.Num)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  ::PROTOBUF_NAMESPACE_ID::RepeatedField< ::PROTOBUF_NAMESPACE_ID::int32 > num_;
  mutable std::atomic<int> _num_cached_byte_size_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_calc_5fadd_2eproto;
};
// -------------------------------------------------------------------

class Addend PROTOBUF_FINAL :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:Calculation.Addend) */ {
 public:
  inline Addend() : Addend(nullptr) {}
  virtual ~Addend();

  Addend(const Addend& from);
  Addend(Addend&& from) noexcept
    : Addend() {
    *this = ::std::move(from);
  }

  inline Addend& operator=(const Addend& from) {
    CopyFrom(from);
    return *this;
  }
  inline Addend& operator=(Addend&& from) noexcept {
    if (GetArena() == from.GetArena()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return GetMetadataStatic().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return GetMetadataStatic().reflection;
  }
  static const Addend& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const Addend* internal_default_instance() {
    return reinterpret_cast<const Addend*>(
               &_Addend_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  friend void swap(Addend& a, Addend& b) {
    a.Swap(&b);
  }
  inline void Swap(Addend* other) {
    if (other == this) return;
    if (GetArena() == other->GetArena()) {
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(Addend* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetArena() == other->GetArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline Addend* New() const final {
    return CreateMaybeMessage<Addend>(nullptr);
  }

  Addend* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<Addend>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const Addend& from);
  void MergeFrom(const Addend& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  inline void SharedCtor();
  inline void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(Addend* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "Calculation.Addend";
  }
  protected:
  explicit Addend(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;
  private:
  static ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadataStatic() {
    ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&::descriptor_table_calc_5fadd_2eproto);
    return ::descriptor_table_calc_5fadd_2eproto.file_level_metadata[kIndexInFileMessages];
  }

  public:

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kLastUpdatedFieldNumber = 3,
    kAdd1FieldNumber = 1,
    kAdd2FieldNumber = 2,
  };
  // .google.protobuf.Timestamp last_updated = 3;
  bool has_last_updated() const;
  private:
  bool _internal_has_last_updated() const;
  public:
  void clear_last_updated();
  const PROTOBUF_NAMESPACE_ID::Timestamp& last_updated() const;
  PROTOBUF_NAMESPACE_ID::Timestamp* release_last_updated();
  PROTOBUF_NAMESPACE_ID::Timestamp* mutable_last_updated();
  void set_allocated_last_updated(PROTOBUF_NAMESPACE_ID::Timestamp* last_updated);
  private:
  const PROTOBUF_NAMESPACE_ID::Timestamp& _internal_last_updated() const;
  PROTOBUF_NAMESPACE_ID::Timestamp* _internal_mutable_last_updated();
  public:
  void unsafe_arena_set_allocated_last_updated(
      PROTOBUF_NAMESPACE_ID::Timestamp* last_updated);
  PROTOBUF_NAMESPACE_ID::Timestamp* unsafe_arena_release_last_updated();

  // int32 add1 = 1;
  void clear_add1();
  ::PROTOBUF_NAMESPACE_ID::int32 add1() const;
  void set_add1(::PROTOBUF_NAMESPACE_ID::int32 value);
  private:
  ::PROTOBUF_NAMESPACE_ID::int32 _internal_add1() const;
  void _internal_set_add1(::PROTOBUF_NAMESPACE_ID::int32 value);
  public:

  // int32 add2 = 2;
  void clear_add2();
  ::PROTOBUF_NAMESPACE_ID::int32 add2() const;
  void set_add2(::PROTOBUF_NAMESPACE_ID::int32 value);
  private:
  ::PROTOBUF_NAMESPACE_ID::int32 _internal_add2() const;
  void _internal_set_add2(::PROTOBUF_NAMESPACE_ID::int32 value);
  public:

  // @@protoc_insertion_point(class_scope:Calculation.Addend)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  PROTOBUF_NAMESPACE_ID::Timestamp* last_updated_;
  ::PROTOBUF_NAMESPACE_ID::int32 add1_;
  ::PROTOBUF_NAMESPACE_ID::int32 add2_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_calc_5fadd_2eproto;
};
// -------------------------------------------------------------------

class Sum PROTOBUF_FINAL :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:Calculation.Sum) */ {
 public:
  inline Sum() : Sum(nullptr) {}
  virtual ~Sum();

  Sum(const Sum& from);
  Sum(Sum&& from) noexcept
    : Sum() {
    *this = ::std::move(from);
  }

  inline Sum& operator=(const Sum& from) {
    CopyFrom(from);
    return *this;
  }
  inline Sum& operator=(Sum&& from) noexcept {
    if (GetArena() == from.GetArena()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return GetMetadataStatic().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return GetMetadataStatic().reflection;
  }
  static const Sum& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const Sum* internal_default_instance() {
    return reinterpret_cast<const Sum*>(
               &_Sum_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    2;

  friend void swap(Sum& a, Sum& b) {
    a.Swap(&b);
  }
  inline void Swap(Sum* other) {
    if (other == this) return;
    if (GetArena() == other->GetArena()) {
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(Sum* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetArena() == other->GetArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline Sum* New() const final {
    return CreateMaybeMessage<Sum>(nullptr);
  }

  Sum* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<Sum>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const Sum& from);
  void MergeFrom(const Sum& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  inline void SharedCtor();
  inline void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(Sum* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "Calculation.Sum";
  }
  protected:
  explicit Sum(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;
  private:
  static ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadataStatic() {
    ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&::descriptor_table_calc_5fadd_2eproto);
    return ::descriptor_table_calc_5fadd_2eproto.file_level_metadata[kIndexInFileMessages];
  }

  public:

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kLastUpdatedFieldNumber = 2,
    kNumFieldNumber = 1,
  };
  // .google.protobuf.Timestamp last_updated = 2;
  bool has_last_updated() const;
  private:
  bool _internal_has_last_updated() const;
  public:
  void clear_last_updated();
  const PROTOBUF_NAMESPACE_ID::Timestamp& last_updated() const;
  PROTOBUF_NAMESPACE_ID::Timestamp* release_last_updated();
  PROTOBUF_NAMESPACE_ID::Timestamp* mutable_last_updated();
  void set_allocated_last_updated(PROTOBUF_NAMESPACE_ID::Timestamp* last_updated);
  private:
  const PROTOBUF_NAMESPACE_ID::Timestamp& _internal_last_updated() const;
  PROTOBUF_NAMESPACE_ID::Timestamp* _internal_mutable_last_updated();
  public:
  void unsafe_arena_set_allocated_last_updated(
      PROTOBUF_NAMESPACE_ID::Timestamp* last_updated);
  PROTOBUF_NAMESPACE_ID::Timestamp* unsafe_arena_release_last_updated();

  // int32 num = 1;
  void clear_num();
  ::PROTOBUF_NAMESPACE_ID::int32 num() const;
  void set_num(::PROTOBUF_NAMESPACE_ID::int32 value);
  private:
  ::PROTOBUF_NAMESPACE_ID::int32 _internal_num() const;
  void _internal_set_num(::PROTOBUF_NAMESPACE_ID::int32 value);
  public:

  // @@protoc_insertion_point(class_scope:Calculation.Sum)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  PROTOBUF_NAMESPACE_ID::Timestamp* last_updated_;
  ::PROTOBUF_NAMESPACE_ID::int32 num_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_calc_5fadd_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// Num

// repeated int32 num = 1;
inline int Num::_internal_num_size() const {
  return num_.size();
}
inline int Num::num_size() const {
  return _internal_num_size();
}
inline void Num::clear_num() {
  num_.Clear();
}
inline ::PROTOBUF_NAMESPACE_ID::int32 Num::_internal_num(int index) const {
  return num_.Get(index);
}
inline ::PROTOBUF_NAMESPACE_ID::int32 Num::num(int index) const {
  // @@protoc_insertion_point(field_get:Calculation.Num.num)
  return _internal_num(index);
}
inline void Num::set_num(int index, ::PROTOBUF_NAMESPACE_ID::int32 value) {
  num_.Set(index, value);
  // @@protoc_insertion_point(field_set:Calculation.Num.num)
}
inline void Num::_internal_add_num(::PROTOBUF_NAMESPACE_ID::int32 value) {
  num_.Add(value);
}
inline void Num::add_num(::PROTOBUF_NAMESPACE_ID::int32 value) {
  _internal_add_num(value);
  // @@protoc_insertion_point(field_add:Calculation.Num.num)
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedField< ::PROTOBUF_NAMESPACE_ID::int32 >&
Num::_internal_num() const {
  return num_;
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedField< ::PROTOBUF_NAMESPACE_ID::int32 >&
Num::num() const {
  // @@protoc_insertion_point(field_list:Calculation.Num.num)
  return _internal_num();
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedField< ::PROTOBUF_NAMESPACE_ID::int32 >*
Num::_internal_mutable_num() {
  return &num_;
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedField< ::PROTOBUF_NAMESPACE_ID::int32 >*
Num::mutable_num() {
  // @@protoc_insertion_point(field_mutable_list:Calculation.Num.num)
  return _internal_mutable_num();
}

// -------------------------------------------------------------------

// Addend

// int32 add1 = 1;
inline void Addend::clear_add1() {
  add1_ = 0;
}
inline ::PROTOBUF_NAMESPACE_ID::int32 Addend::_internal_add1() const {
  return add1_;
}
inline ::PROTOBUF_NAMESPACE_ID::int32 Addend::add1() const {
  // @@protoc_insertion_point(field_get:Calculation.Addend.add1)
  return _internal_add1();
}
inline void Addend::_internal_set_add1(::PROTOBUF_NAMESPACE_ID::int32 value) {
  
  add1_ = value;
}
inline void Addend::set_add1(::PROTOBUF_NAMESPACE_ID::int32 value) {
  _internal_set_add1(value);
  // @@protoc_insertion_point(field_set:Calculation.Addend.add1)
}

// int32 add2 = 2;
inline void Addend::clear_add2() {
  add2_ = 0;
}
inline ::PROTOBUF_NAMESPACE_ID::int32 Addend::_internal_add2() const {
  return add2_;
}
inline ::PROTOBUF_NAMESPACE_ID::int32 Addend::add2() const {
  // @@protoc_insertion_point(field_get:Calculation.Addend.add2)
  return _internal_add2();
}
inline void Addend::_internal_set_add2(::PROTOBUF_NAMESPACE_ID::int32 value) {
  
  add2_ = value;
}
inline void Addend::set_add2(::PROTOBUF_NAMESPACE_ID::int32 value) {
  _internal_set_add2(value);
  // @@protoc_insertion_point(field_set:Calculation.Addend.add2)
}

// .google.protobuf.Timestamp last_updated = 3;
inline bool Addend::_internal_has_last_updated() const {
  return this != internal_default_instance() && last_updated_ != nullptr;
}
inline bool Addend::has_last_updated() const {
  return _internal_has_last_updated();
}
inline const PROTOBUF_NAMESPACE_ID::Timestamp& Addend::_internal_last_updated() const {
  const PROTOBUF_NAMESPACE_ID::Timestamp* p = last_updated_;
  return p != nullptr ? *p : *reinterpret_cast<const PROTOBUF_NAMESPACE_ID::Timestamp*>(
      &PROTOBUF_NAMESPACE_ID::_Timestamp_default_instance_);
}
inline const PROTOBUF_NAMESPACE_ID::Timestamp& Addend::last_updated() const {
  // @@protoc_insertion_point(field_get:Calculation.Addend.last_updated)
  return _internal_last_updated();
}
inline void Addend::unsafe_arena_set_allocated_last_updated(
    PROTOBUF_NAMESPACE_ID::Timestamp* last_updated) {
  if (GetArena() == nullptr) {
    delete reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(last_updated_);
  }
  last_updated_ = last_updated;
  if (last_updated) {
    
  } else {
    
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:Calculation.Addend.last_updated)
}
inline PROTOBUF_NAMESPACE_ID::Timestamp* Addend::release_last_updated() {
  
  PROTOBUF_NAMESPACE_ID::Timestamp* temp = last_updated_;
  last_updated_ = nullptr;
  if (GetArena() != nullptr) {
    temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
  }
  return temp;
}
inline PROTOBUF_NAMESPACE_ID::Timestamp* Addend::unsafe_arena_release_last_updated() {
  // @@protoc_insertion_point(field_release:Calculation.Addend.last_updated)
  
  PROTOBUF_NAMESPACE_ID::Timestamp* temp = last_updated_;
  last_updated_ = nullptr;
  return temp;
}
inline PROTOBUF_NAMESPACE_ID::Timestamp* Addend::_internal_mutable_last_updated() {
  
  if (last_updated_ == nullptr) {
    auto* p = CreateMaybeMessage<PROTOBUF_NAMESPACE_ID::Timestamp>(GetArena());
    last_updated_ = p;
  }
  return last_updated_;
}
inline PROTOBUF_NAMESPACE_ID::Timestamp* Addend::mutable_last_updated() {
  // @@protoc_insertion_point(field_mutable:Calculation.Addend.last_updated)
  return _internal_mutable_last_updated();
}
inline void Addend::set_allocated_last_updated(PROTOBUF_NAMESPACE_ID::Timestamp* last_updated) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArena();
  if (message_arena == nullptr) {
    delete reinterpret_cast< ::PROTOBUF_NAMESPACE_ID::MessageLite*>(last_updated_);
  }
  if (last_updated) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
      reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(last_updated)->GetArena();
    if (message_arena != submessage_arena) {
      last_updated = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, last_updated, submessage_arena);
    }
    
  } else {
    
  }
  last_updated_ = last_updated;
  // @@protoc_insertion_point(field_set_allocated:Calculation.Addend.last_updated)
}

// -------------------------------------------------------------------

// Sum

// int32 num = 1;
inline void Sum::clear_num() {
  num_ = 0;
}
inline ::PROTOBUF_NAMESPACE_ID::int32 Sum::_internal_num() const {
  return num_;
}
inline ::PROTOBUF_NAMESPACE_ID::int32 Sum::num() const {
  // @@protoc_insertion_point(field_get:Calculation.Sum.num)
  return _internal_num();
}
inline void Sum::_internal_set_num(::PROTOBUF_NAMESPACE_ID::int32 value) {
  
  num_ = value;
}
inline void Sum::set_num(::PROTOBUF_NAMESPACE_ID::int32 value) {
  _internal_set_num(value);
  // @@protoc_insertion_point(field_set:Calculation.Sum.num)
}

// .google.protobuf.Timestamp last_updated = 2;
inline bool Sum::_internal_has_last_updated() const {
  return this != internal_default_instance() && last_updated_ != nullptr;
}
inline bool Sum::has_last_updated() const {
  return _internal_has_last_updated();
}
inline const PROTOBUF_NAMESPACE_ID::Timestamp& Sum::_internal_last_updated() const {
  const PROTOBUF_NAMESPACE_ID::Timestamp* p = last_updated_;
  return p != nullptr ? *p : *reinterpret_cast<const PROTOBUF_NAMESPACE_ID::Timestamp*>(
      &PROTOBUF_NAMESPACE_ID::_Timestamp_default_instance_);
}
inline const PROTOBUF_NAMESPACE_ID::Timestamp& Sum::last_updated() const {
  // @@protoc_insertion_point(field_get:Calculation.Sum.last_updated)
  return _internal_last_updated();
}
inline void Sum::unsafe_arena_set_allocated_last_updated(
    PROTOBUF_NAMESPACE_ID::Timestamp* last_updated) {
  if (GetArena() == nullptr) {
    delete reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(last_updated_);
  }
  last_updated_ = last_updated;
  if (last_updated) {
    
  } else {
    
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:Calculation.Sum.last_updated)
}
inline PROTOBUF_NAMESPACE_ID::Timestamp* Sum::release_last_updated() {
  
  PROTOBUF_NAMESPACE_ID::Timestamp* temp = last_updated_;
  last_updated_ = nullptr;
  if (GetArena() != nullptr) {
    temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
  }
  return temp;
}
inline PROTOBUF_NAMESPACE_ID::Timestamp* Sum::unsafe_arena_release_last_updated() {
  // @@protoc_insertion_point(field_release:Calculation.Sum.last_updated)
  
  PROTOBUF_NAMESPACE_ID::Timestamp* temp = last_updated_;
  last_updated_ = nullptr;
  return temp;
}
inline PROTOBUF_NAMESPACE_ID::Timestamp* Sum::_internal_mutable_last_updated() {
  
  if (last_updated_ == nullptr) {
    auto* p = CreateMaybeMessage<PROTOBUF_NAMESPACE_ID::Timestamp>(GetArena());
    last_updated_ = p;
  }
  return last_updated_;
}
inline PROTOBUF_NAMESPACE_ID::Timestamp* Sum::mutable_last_updated() {
  // @@protoc_insertion_point(field_mutable:Calculation.Sum.last_updated)
  return _internal_mutable_last_updated();
}
inline void Sum::set_allocated_last_updated(PROTOBUF_NAMESPACE_ID::Timestamp* last_updated) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArena();
  if (message_arena == nullptr) {
    delete reinterpret_cast< ::PROTOBUF_NAMESPACE_ID::MessageLite*>(last_updated_);
  }
  if (last_updated) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
      reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(last_updated)->GetArena();
    if (message_arena != submessage_arena) {
      last_updated = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, last_updated, submessage_arena);
    }
    
  } else {
    
  }
  last_updated_ = last_updated;
  // @@protoc_insertion_point(field_set_allocated:Calculation.Sum.last_updated)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------

// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)

}  // namespace Calculation

// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_calc_5fadd_2eproto