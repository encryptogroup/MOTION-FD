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

#include "base/backend.h"
#include "base/register.h"
#include "communication/communication_layer.h"
#include "communication/message.h"
#include "protocols/astra/astra_wire.h"
#include "protocols/boolean_astra/boolean_astra_wire.h"
#include "protocols/share_wrapper.h"
#include <boost/numeric/ublas/matrix.hpp>

namespace encrypto::motion::proto::astra { 
    
constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max(); 

template <typename T>
class InputGate final : public motion::InputGate {
  using Base = motion::InputGate;

 public:
  InputGate(std::vector<T> input, std::size_t input_owner, Backend& backend);

  ~InputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> input_future_;
};

template <typename T>
class OutputGate final : public motion::OutputGate {
  using Base = motion::OutputGate;

 public:
  OutputGate(const astra::SharePointer<T>& parent, std::size_t output_owner);
  OutputGate(const astra::WirePointer<T>& parent, std::size_t output_owner = kAll);
  OutputGate(const motion::SharePointer& parent, std::size_t output_owner);

  ~OutputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }
  
  astra::SharePointer<T> GetOutputAsAstraShare();
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> output_future_;
};

template<typename T>
class AdditionGate final : public TwoGate {
  using Base = motion::TwoGate;
 
 public:
  AdditionGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b);
  
  ~AdditionGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
};

template<typename T>
class SubtractionGate final : public TwoGate {
  using Base = motion::TwoGate;
 
 public:
  SubtractionGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b);
  
  ~SubtractionGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
};

template<typename T>
class MultiplicationGate final : public TwoGate {
  using Base = motion::TwoGate;
 
 public:
  MultiplicationGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b);
  
  ~MultiplicationGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> multiply_future_setup_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> multiply_future_online_;
};

template<typename T>
class DotProductGate final : public TwoGate {
  using Base = motion::TwoGate;
 public:
  DotProductGate(std::vector<motion::WirePointer> vector_a, std::vector<motion::WirePointer> vector_b);

  ~DotProductGate() final = default;

  DotProductGate(DotProductGate const&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> dot_product_future_setup_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> dot_product_future_online_;
};

template<typename T>
class MatrixConversionGate final : public motion::Gate {
  using Base = motion::Gate;
 public:
  MatrixConversionGate(boost::numeric::ublas::matrix<ShareWrapper> const& wires);
  
  ~MatrixConversionGate() final = default;

  MatrixConversionGate(MatrixConversionGate&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
 private:
  boost::numeric::ublas::matrix<ShareWrapper> wires_;
};

template<typename T>
class MatrixReconversionGate final : public motion::Gate {
  using Base = motion::Gate;
 public:
  MatrixReconversionGate(ShareWrapper const& share_wrapper);
  
  ~MatrixReconversionGate() final = default;

  MatrixReconversionGate(MatrixReconversionGate&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  boost::numeric::ublas::matrix<ShareWrapper> const& GetShareMatrix() const {
    return share_matrix_;
  }
  
 private:
  boost::numeric::ublas::matrix<ShareWrapper> share_matrix_;
  astra::MatrixWirePointer<T> matrix_input_wire_;
};

template<typename T>
class MatrixSimdReconversionGate final : public motion::Gate {
  using Base = motion::Gate;
 public:
  MatrixSimdReconversionGate(ShareWrapper const& share_wrapper);
  
  ~MatrixSimdReconversionGate() final = default;

  MatrixSimdReconversionGate(MatrixSimdReconversionGate&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  ShareWrapper const& GetSimdShare() const {
    return simd_share_;
  }
  
 private:
  ShareWrapper simd_share_;
  astra::MatrixWirePointer<T> matrix_input_wire_;
};

template<typename T>
class MatrixMultiplicationGate final : public TwoGate {
  using Base = motion::TwoGate;
 public:
  MatrixMultiplicationGate(MatrixWirePointer<T> matrix_a, MatrixWirePointer<T> matrix_b);

  ~MatrixMultiplicationGate() final = default;

  MatrixMultiplicationGate(MatrixMultiplicationGate const&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> matrix_multiply_future_setup_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> matrix_multiply_future_online_;
};

template<typename T>
class BitAGate final : public OneGate {
  using Base = motion::OneGate;
 public:
  BitAGate(boolean_astra::BitMatrixWirePointer bit_matrix_wire);

  ~BitAGate() final = default;

  BitAGate(BitAGate const&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> bit_a_future_setup_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> bit_a_future_online_;
};

template<typename T>
class B2AGate final : public OneGate {
  using Base = motion::OneGate;
 public:
  B2AGate(std::vector<motion::WirePointer> bit_wires);

  ~B2AGate() final = default;

  B2AGate(B2AGate const&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
 private:
  std::vector<T> r_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> b2a_future_setup_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> b2a_future_online_;
};

//The MsbGate currently returns inverted msb value, so if e.g. 1 
//is the msb of the input then MsbGate will return 0 and vice-versa.
template<typename T>
class MsbGate final : public motion::OneGate {
  using Base = motion::OneGate;
 public:
  MsbGate(MatrixWirePointer<T> const& matrix_wire);

  ~MsbGate() final = default;

  MsbGate(MsbGate const&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  boolean_astra::SharePointer GetOutputAsBooleanAstraShare();
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> msb_future_setup_;
  std::vector<boost::numeric::ublas::matrix<T>> R1_, R2_;
  ShareWrapper A_, B_, PPA_;
};

namespace fixed_point {
    
template<typename T>
class MatrixConstantMultiplicationGate final : public Gate {
  using Base = motion::Gate;
 public:
  MatrixConstantMultiplicationGate(T constant, MatrixWirePointer<T> matrix_a, unsigned precision);

  ~MatrixConstantMultiplicationGate() final = default;

  MatrixConstantMultiplicationGate(MatrixConstantMultiplicationGate&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> matrix_multiply_future_setup_;
  MatrixWirePointer<T> parent_a_;
  T constant_;
  unsigned precision_;
};

template<typename T>
class MatrixMultiplicationGate final : public TwoGate {
  using Base = motion::TwoGate;
 public:
  MatrixMultiplicationGate(MatrixWirePointer<T> matrix_a, MatrixWirePointer<T> matrix_b, unsigned precision);

  ~MatrixMultiplicationGate() final = default;

  MatrixMultiplicationGate(MatrixMultiplicationGate const&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> matrix_multiply_future_setup_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> matrix_multiply_future_online_;
  unsigned precision_;
};

} //namespace fixed_point

} //namespace encrypto::motion::proto::astra