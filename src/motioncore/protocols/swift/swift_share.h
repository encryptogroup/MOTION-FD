#pragma once

#include "astra_wire.h"
#include "protocols/share.h"


namespace encrypto::motion::proto::astra {
    
template <typename T>
class Share final : public motion::Share {
  using Base = motion::Share;

 public:
  Share(const motion::WirePointer& wire);
  Share(const astra::WirePointer<T>& wire);
  Share(const std::vector<astra::WirePointer<T>>& wires);
  Share(const std::vector<motion::WirePointer>& wires);

  ~Share() override = default;

  std::size_t GetNumberOfSimdValues() const noexcept final;

  MpcProtocol GetProtocol() const noexcept final;

  CircuitType GetCircuitType() const noexcept final;

  astra::WirePointer<T> GetAstraWire() {
    auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(wires_[0]);
    assert(wire);
    return wire;
  }

  const std::vector<motion::WirePointer>& GetWires() const noexcept final { return wires_; }

  std::vector<motion::WirePointer>& GetMutableWires() noexcept final { return wires_; }

  bool Finished();

  std::size_t GetBitLength() const noexcept final { return sizeof(T) * CHAR_BIT; }

  std::vector<std::shared_ptr<Base>> Split() const noexcept final;

  std::shared_ptr<Base> GetWire(std::size_t i) const override;

  Share(Share&) = delete;

 private:
  Share() = default;
};

template <typename T>
using SharePointer = std::shared_ptr<Share<T>>;

}  // namespace encrypto::motion::proto::astra