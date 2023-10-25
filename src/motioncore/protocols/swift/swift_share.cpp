#include "astra_share.h"

#include <fmt/format.h>

namespace encrypto::motion::proto::astra {

template <typename T>
Share<T>::Share(const motion::WirePointer& wire) : Base(wire->GetBackend()) {
  wires_ = {wire};
  if (!wires_.at(0)) {
    throw(std::runtime_error("Something went wrong with creating an astra share"));
  }
}

template <typename T>
Share<T>::Share(const astra::WirePointer<T>& wire) : Base(wire->GetBackend()) {
  wires_ = {std::static_pointer_cast<motion::Wire>(wire)};
}

template <typename T>
Share<T>::Share(const std::vector<astra::WirePointer<T>>& wires)
    : Base(wires.at(0)->GetBackend()) {
  for (auto i = 0ull; i < wires.size(); ++i) {
    wires_.emplace_back(wires.at(i));
  }
  if (wires.size() == 0) {
    throw(std::runtime_error("Trying to create an astra share without wires"));
  }
  if (wires.size() > 1) {
    throw(
        std::runtime_error(fmt::format("Cannot create an astra share "
                                       "from more than 1 wire; got {} wires",
                                       wires.size())));
  }
}

template <typename T>
Share<T>::Share(const std::vector<motion::WirePointer>& wires) : Base(wires.at(0)->GetBackend()) {
  if (wires.size() == 0) {
    throw(std::runtime_error("Trying to create an astra share without wires"));
  }
  if (wires.size() > 1) {
    throw(
        std::runtime_error(fmt::format("Cannot create an astra share "
                                       "from more than 1 wire; got {} wires",
                                       wires.size())));
  }
  wires_ = {wires.at(0)};
  if (!wires_.at(0)) {
    throw(std::runtime_error("Something went wrong with creating an astra share"));
  }
}

template <typename T>
std::size_t Share<T>::GetNumberOfSimdValues() const noexcept {
  return wires_.at(0)->GetNumberOfSimdValues();
}

template <typename T>
MpcProtocol Share<T>::GetProtocol() const noexcept {
  assert(wires_.at(0)->GetProtocol() == MpcProtocol::kAstra);
  return wires_.at(0)->GetProtocol();
}

template <typename T>
CircuitType Share<T>::GetCircuitType() const noexcept {
  assert(wires_.at(0)->GetCircuitType() == CircuitType::kArithmetic);
  return wires_.at(0)->GetCircuitType();
}

template <typename T>
bool Share<T>::Finished() {
  return wires_.at(0)->IsReady();
}

template <typename T>
std::vector<std::shared_ptr<motion::Share>> Share<T>::Split() const noexcept {
  std::vector<std::shared_ptr<Base>> v;
  v.reserve(wires_.size());
  for (const auto& w : wires_) {
    const std::vector<motion::WirePointer> w_v = {std::static_pointer_cast<motion::Wire>(w)};
    v.emplace_back(std::make_shared<Share<T>>(w_v));
  }
  return v;
}

template <typename T>
std::shared_ptr<motion::Share> Share<T>::GetWire(std::size_t i) const {
  if (i >= wires_.size()) {
    throw std::out_of_range(
        fmt::format("Trying to access wire #{} out of {} wires", i, wires_.size()));
  }
  std::vector<motion::WirePointer> result = {std::static_pointer_cast<motion::Wire>(wires_[i])};
  return std::make_shared<Share<T>>(result);
}

template class Share<std::uint8_t>;
template class Share<std::uint16_t>;
template class Share<std::uint32_t>;
template class Share<std::uint64_t>;
template class Share<__uint128_t>;

}  // namespace encrypto::motion::proto::astra
