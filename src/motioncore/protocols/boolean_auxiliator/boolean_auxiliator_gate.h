#pragma once

#include "base/backend.h"
#include "base/register.h"
#include "communication/communication_layer.h"
#include "communication/message.h"
#include "boolean_auxiliator_wire.h"
#include "boolean_auxiliator_share.h"
#include "utility/bit_vector.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/auxiliator/auxiliator_verifier.h"

namespace encrypto::motion {
  class ShareWrapper;
}  // namespace encrypto::motion

namespace encrypto::motion::proto::boolean_auxiliator {
    
constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max(); 

class InputGate final : public motion::InputGate {
  using Base = motion::InputGate;

 public:
  InputGate(std::vector<BitVector<>> input, std::size_t input_owner, Backend& backend);

  ~InputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  boolean_auxiliator::SharePointer GetOutputAsBooleanAuxiliatorShare();
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> input_future_;
};

class OutputGate final : public motion::OutputGate {
  using Base = motion::OutputGate;

 public:
  OutputGate(ShareWrapper const& parent, std::size_t output_owner = kAll);

  ~OutputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  boolean_auxiliator::SharePointer GetOutputAsBooleanAuxiliatorShare();
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> output_future_;
};

class XorGate final : public motion::TwoGate {
  using Base = motion::TwoGate;
 
 public:
  XorGate(ShareWrapper const& a, ShareWrapper const& b);
  
  ~XorGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  boolean_auxiliator::SharePointer GetOutputAsBooleanAuxiliatorShare();
};

class AndGate final : public motion::TwoGate {
  using Base = motion::TwoGate;
 
 public:
  AndGate(ShareWrapper const& a, ShareWrapper const& b);
  
  ~AndGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  boolean_auxiliator::SharePointer GetOutputAsBooleanAuxiliatorShare();
  
 private:
  motion::AuxiliatorSacrificeVerifier::ReservedTriple64 triple_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> multiply_future_online_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> multiply_future_setup_;
};

} //namespace encrypto::motion::proto::boolean_auxiliator