#include "astra_wire.h"

namespace encrypto::motion::proto::astra {

template<typename T>
Wire<T>::Wire(Backend& backend, std::vector<Data> values)
  : Base(backend, values.size()), values_{std::move(values)}, 
    setup_ready_condition_{std::make_unique<FiberCondition>([this]() { return setup_ready_.load(); })} {}

template<typename T>
Wire<T>::Wire(Backend& backend, std::size_t number_of_simd)
  : Base(backend, number_of_simd), values_(number_of_simd), 
    setup_ready_condition_{std::make_unique<FiberCondition>([this]() { return setup_ready_.load(); })} {}

template class Wire<std::uint8_t>;
template class Wire<std::uint16_t>;
template class Wire<std::uint32_t>;
template class Wire<std::uint64_t>;
template class Wire<__uint128_t>;

template<typename T>
MatrixWire<T>::MatrixWire(Backend& backend, size_t m, size_t n, size_t number_of_simd_values)
: Base(backend, number_of_simd_values), 
  setup_ready_condition_{std::make_unique<FiberCondition>([this]() { return setup_ready_.load(); })} {
  value_matrices.reserve(number_of_simd_values);
  lambda_matrices.reserve(number_of_simd_values);
  for(size_t i = 0; i != number_of_simd_values; ++i) {
    value_matrices.emplace_back(m, n);
    lambda_matrices.emplace_back(m, n);
  }
}

template class MatrixWire<std::uint8_t>;
template class MatrixWire<std::uint16_t>;
template class MatrixWire<std::uint32_t>;
template class MatrixWire<std::uint64_t>;
template class MatrixWire<__uint128_t>;
    
} // namespace encrypto::motion::proto::astra