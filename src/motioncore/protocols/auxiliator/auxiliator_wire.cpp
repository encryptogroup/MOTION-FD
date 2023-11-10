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

#include "auxiliator_wire.h"

namespace encrypto::motion::proto::auxiliator {

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
    
} // namespace encrypto::motion::proto::auxiliator