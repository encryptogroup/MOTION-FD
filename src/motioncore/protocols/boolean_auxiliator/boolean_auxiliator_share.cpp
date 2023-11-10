#include "boolean_auxiliator_share.h"
#include "boolean_auxiliator_gate.h"
#include "base/register.h"

namespace encrypto::motion::proto::boolean_auxiliator {

Share::Share(const motion::WirePointer& wire) 
: Base( (assert(wire), wire->GetBackend()) ) {
  wires_ = {wire};
}

Share::Share(const boolean_auxiliator::WirePointer& wire)
: Base( (assert(wire), wire->GetBackend()) ) {
  wires_ = {std::static_pointer_cast<motion::Wire>(wire)};
}

Share::Share(std::vector<boolean_auxiliator::WirePointer> const& wires)
: Base( (assert(wires.size() > 0), wires[0]->GetBackend()) ) {
  for (size_t s = 0; s != wires.size(); ++s) {
    wires_.emplace_back(wires[s]);
  }
}

Share::Share(std::vector<motion::WirePointer> const& wires)
: Base( (assert(wires.size() > 0), wires[0]->GetBackend()) ) {
  for (size_t s = 0; s != wires.size(); ++s) {
    wires_.emplace_back(wires[s]);
  }
}

std::size_t Share::GetNumberOfSimdValues() const noexcept {
  return wires_[0]->GetNumberOfSimdValues();
}

MpcProtocol Share::GetProtocol() const noexcept {
  assert(wires_[0]->GetProtocol() == MpcProtocol::kBooleanAuxiliator);
  return wires_[0]->GetProtocol();
}

CircuitType Share::GetCircuitType() const noexcept {
  assert(wires_[0]->GetCircuitType() == CircuitType::kBoolean);
  return wires_[0]->GetCircuitType();
}

bool Share::Finished() {
  return wires_[0]->IsReady();
}

std::vector<std::shared_ptr<motion::Share>> Share::Split() const noexcept {
  std::vector<motion::SharePointer> v;
  v.reserve(wires_.size());
  for (const auto& w : wires_) {
    const std::vector<motion::WirePointer> w_v = {std::static_pointer_cast<motion::Wire>(w)};
    v.emplace_back(std::make_shared<Share>(w_v));
  }
  return v;
}

std::shared_ptr<motion::Share> Share::GetWire(std::size_t i) const {
  if (i >= wires_.size()) {
    throw std::out_of_range(
        fmt::format("Trying to access wire #{} out of {} wires", i, wires_.size()));
  }
  std::vector<motion::WirePointer> result = {std::static_pointer_cast<motion::Wire>(wires_[i])};
  return std::make_shared<Share>(result);
}

}  // namespace encrypto::motion::proto::boolean_auxiliator
