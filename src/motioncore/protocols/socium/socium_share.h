// MIT License
//
// Copyright (c) 2023 Oliver Schick
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include "socium_wire.h"
#include "protocols/share.h"


namespace encrypto::motion::proto::socium {
    
template <typename T>
class Share final : public motion::Share {
  using Base = motion::Share;

 public:
  Share(const motion::WirePointer& wire);
  Share(const socium::WirePointer<T>& wire);
  Share(const std::vector<socium::WirePointer<T>>& wires);
  Share(const std::vector<motion::WirePointer>& wires);

  ~Share() override = default;

  std::size_t GetNumberOfSimdValues() const noexcept final;

  MpcProtocol GetProtocol() const noexcept final;

  CircuitType GetCircuitType() const noexcept final;

  socium::WirePointer<T> GetSociumWire() {
    auto wire = std::dynamic_pointer_cast<socium::Wire<T>>(wires_[0]);
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

class BooleanShare final : public motion::BooleanShare {
  using Base = motion::BooleanShare;

 public:
  BooleanShare(const motion::WirePointer& wire);
  
  BooleanShare(const socium::BooleanWirePointer& wire);
  
  BooleanShare(const std::vector<socium::BooleanWirePointer>& wires);
  
  BooleanShare(const std::vector<motion::WirePointer>& wires);

  ~BooleanShare() override = default;

  std::size_t GetNumberOfSimdValues() const noexcept final;

  MpcProtocol GetProtocol() const noexcept final;

  CircuitType GetCircuitType() const noexcept final;

  const std::vector<motion::WirePointer>& GetWires() const noexcept final { return wires_; }

  std::vector<motion::WirePointer>& GetMutableWires() noexcept final { return wires_; }

  bool Finished();

  std::size_t GetBitLength() const noexcept final { return wires_.size(); }

  std::vector<motion::SharePointer> Split() const noexcept final;

  motion::SharePointer GetWire(std::size_t i) const override;

  BooleanShare(BooleanShare&) = delete;

 private:
  BooleanShare() = default;
};

using BooleanSharePointer = std::shared_ptr<BooleanShare>;

}  // namespace encrypto::motion::proto::socium