#pragma once

#include "boolean_auxiliator_wire.h"
#include "protocols/share.h"


namespace encrypto::motion::proto::boolean_auxiliator {
    
class Share final : public motion::BooleanShare {
  using Base = motion::BooleanShare;

 public:
  Share(const motion::WirePointer& wire);
  
  Share(const boolean_auxiliator::WirePointer& wire);
  
  Share(const std::vector<boolean_auxiliator::WirePointer>& wires);
  
  Share(const std::vector<motion::WirePointer>& wires);

  ~Share() override = default;

  std::size_t GetNumberOfSimdValues() const noexcept final;

  MpcProtocol GetProtocol() const noexcept final;

  CircuitType GetCircuitType() const noexcept final;

  const std::vector<motion::WirePointer>& GetWires() const noexcept final { return wires_; }

  std::vector<motion::WirePointer>& GetMutableWires() noexcept final { return wires_; }

  bool Finished();

  std::size_t GetBitLength() const noexcept final { return wires_.size(); }

  std::vector<motion::SharePointer> Split() const noexcept final;

  motion::SharePointer GetWire(std::size_t i) const override;

  Share(Share&) = delete;

 private:
  Share() = default;
};

using SharePointer = std::shared_ptr<boolean_auxiliator::Share>;

}  // namespace encrypto::motion::proto::boolean_auxiliator