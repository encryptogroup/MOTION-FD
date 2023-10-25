#include "swift_wire.h"

namespace encrypto::motion::proto::swift {

template<typename T>
Wire<T>::Wire(Backend& backend, size_t number_of_simd_values, 
              std::vector<T> values, std::vector<T> lambda_my_id, std::vector<T> lambda_previous_id)
  : Base(backend, number_of_simd_values), 
    data_{std::move(values), std::move(lambda_my_id), std::move(lambda_previous_id)}, 
    setup_ready_condition_{std::make_unique<FiberCondition>(
                             [this]() { return setup_ready_.load(); })} {}

template<typename T>
Wire<T>::Wire(Backend& backend, size_t number_of_simd_values)
  : Base(backend, number_of_simd_values), 
    data_{}, 
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
  lambda_my_id_matrices.reserve(number_of_simd_values);
  lambda_previous_id_matrices.reserve(number_of_simd_values);
  for(size_t i = 0; i != number_of_simd_values; ++i) {
    value_matrices.emplace_back(m, n);
    lambda_my_id_matrices.emplace_back(m, n);
    lambda_previous_id_matrices.emplace_back(m, n);
  }
}

template class MatrixWire<std::uint8_t>;
template class MatrixWire<std::uint16_t>;
template class MatrixWire<std::uint32_t>;
template class MatrixWire<std::uint64_t>;
template class MatrixWire<__uint128_t>;



BooleanWire::BooleanWire(
  Backend& backend, BitVector<> values, 
  BitVector<> lambdas_my_id, BitVector<> lambdas_previous_id)
  : Base(backend, values.GetSize()), values_{std::move(values)}, 
    lambdas_my_id_{std::move(lambdas_my_id)}, 
    lambdas_previous_id_{std::move(lambdas_previous_id)}, 
    setup_ready_condition_{std::make_unique<FiberCondition>([this]() { return setup_ready_.load(); })} {
  assert(0 < values_.GetSize());      
  assert(lambdas_my_id_.GetSize() == values_.GetSize());     
  assert(lambdas_previous_id_.GetSize() == values_.GetSize());     
}

BitMatrixWire::BitMatrixWire(
  Backend& backend, BitVector<> values, 
  BitVector<> lambdas_my_id, BitVector<> lambdas_previous_id,
  size_t m, size_t n, size_t matrix_simd_values)
: Base(backend, std::move(values), std::move(lambdas_my_id), 
       std::move(lambdas_previous_id)),
  m_(m), n_(n), matrix_simd_values_(matrix_simd_values) {}

    
} // namespace encrypto::motion::proto::swift