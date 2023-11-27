// MIT License
//
// Copyright (c) 2023 Oliver Schick, Andreas Brüggemann
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
#include "protocols/swift/swift_wire.h"
#include "protocols/share_wrapper.h"
#include <boost/numeric/ublas/matrix.hpp>

#include "swift_truncation.h"
#include "swift_verifier.h"

namespace encrypto::motion::proto::swift { 
    
constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max(); 

template <typename T>
class InputGate final : public motion::InputGate {
  using Base = motion::InputGate;

 public:
  InputGate(std::vector<T> input, std::size_t input_owner, Backend& backend);

  ~InputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> input_future_;
  SwiftHashVerifier::ReservedData verifier_hash_data_;
};

template <typename T>
class OutputGate final : public motion::OutputGate {
  using Base = motion::OutputGate;

 public:
  OutputGate(swift::WirePointer<T> const& parent, std::size_t output_owner = kAll);

  ~OutputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> lambda_i_plus_1_future_;
  SwiftHashVerifier::ReservedData verifier_message_hash_data_, verifier_check_hash_data_;
};

template<typename T>
class AdditionGate final : public TwoGate {
  using Base = motion::TwoGate;
 
 public:
  AdditionGate(swift::WirePointer<T> const& a, swift::WirePointer<T> const& b);
  
  ~AdditionGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
};

template<typename T>
class MultiplicationGate final : public TwoGate {
  using Base = motion::TwoGate;
 
 public:
  MultiplicationGate(swift::WirePointer<T> const& a, swift::WirePointer<T> const& b);
  
  ~MultiplicationGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
 private:
  std::vector<T> gamma_xy_my_id_, gamma_xy_previous_id_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> multiply_future_setup_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> multiply_future_online_;
  SwiftSacrificeVerifier::ReservedTriple128 triple_;
  SwiftHashVerifier::ReservedData verifier_received_hash_data_;
  SwiftHashVerifier::ReservedData verifier_s1_message_data_;
  SwiftHashVerifier::ReservedData verifier_s2_message_data_;
};

class AndGate final : public TwoGate {
  using Base = motion::TwoGate;
 
 public:
  AndGate(swift::BooleanWirePointer const& a, swift::BooleanWirePointer const& b);
  
  ~AndGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
 private:
  BitVector<> gamma_xy_my_id_, gamma_xy_previous_id_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> multiply_future_setup_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> multiply_future_online_;
  SwiftSacrificeVerifier::ReservedTriple64 triple_;
  SwiftHashVerifier::ReservedData verifier_received_hash_data_;
  SwiftHashVerifier::ReservedData verifier_s1_message_data_;
  SwiftHashVerifier::ReservedData verifier_s2_message_data_;
};

class XorGate final : public TwoGate {
  using Base = motion::TwoGate;
 
 public:
  XorGate(swift::BooleanWirePointer const& a, swift::BooleanWirePointer const& b);
  
  ~XorGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
};

template<typename T>
class MatrixConversionGate final : public motion::Gate {
  using Base = motion::Gate;
 public:
  MatrixConversionGate(boost::numeric::ublas::matrix<swift::WirePointer<T>> wires);
  
  ~MatrixConversionGate() final = default;

  MatrixConversionGate(MatrixConversionGate&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
 private:
  boost::numeric::ublas::matrix<swift::WirePointer<T>> wires_;
};

template<typename T>
class MatrixReconversionGate final : public motion::Gate {
  using Base = motion::Gate;
 public:
  MatrixReconversionGate(swift::MatrixWirePointer<T> const& matrix_wire);
  
  ~MatrixReconversionGate() final = default;

  MatrixReconversionGate(MatrixReconversionGate&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  boost::numeric::ublas::matrix<swift::WirePointer<T>> const& GetWireMatrix() const {
    return wire_matrix_;
  }
  
 private:
  boost::numeric::ublas::matrix<swift::WirePointer<T>> wire_matrix_;
  swift::MatrixWirePointer<T> matrix_input_wire_;
};

template<typename T>
class MatrixSimdReconversionGate final : public motion::Gate {
  using Base = motion::Gate;
 public:
  MatrixSimdReconversionGate(swift::MatrixWirePointer<T> const& matrix_wire);
  
  ~MatrixSimdReconversionGate() final = default;

  MatrixSimdReconversionGate(MatrixSimdReconversionGate&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  swift::WirePointer<T> const& GetWire() const {
    return wire_;
  }
  
 private:
  swift::WirePointer<T> wire_;
  swift::MatrixWirePointer<T> matrix_input_wire_;
};

template<typename T>
class MatrixMultiplicationGate final : public TwoGate {
  using Base = motion::TwoGate;
 public:
  MatrixMultiplicationGate(swift::MatrixWirePointer<T> matrix_a, 
                           swift::MatrixWirePointer<T> matrix_b);

  ~MatrixMultiplicationGate() final = default;

  MatrixMultiplicationGate(MatrixMultiplicationGate const&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

 private:
  std::vector<boost::numeric::ublas::matrix<T>> 
    matrix_gamma_xy_my_id_, matrix_gamma_xy_previous_id_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> matrix_multiply_future_setup_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> matrix_multiply_future_online_;
  SwiftSacrificeVerifier::ReservedMatrixTriple128 triple_;
  SwiftHashVerifier::ReservedData verifier_received_hash_data_;
  SwiftHashVerifier::ReservedData verifier_s1_message_data_;
  SwiftHashVerifier::ReservedData verifier_s2_message_data_;
};

template<typename T>
class FpaMatrixMultiplicationGate final : public TwoGate {
  using Base = motion::TwoGate;
 public:
  FpaMatrixMultiplicationGate(swift::MatrixWirePointer<T> matrix_a, 
                           swift::MatrixWirePointer<T> matrix_b);

  ~FpaMatrixMultiplicationGate() final = default;

  FpaMatrixMultiplicationGate(FpaMatrixMultiplicationGate const&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

 private:
  std::vector<boost::numeric::ublas::matrix<T>> 
    matrix_gamma_xy_my_id_, matrix_gamma_xy_previous_id_, 
    matrix_lambda_wd_0_, matrix_lambda_wd_1_, matrix_lambda_wd_2_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> matrix_multiply_future_setup_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> matrix_multiply_future_online_;
  SwiftSacrificeVerifier::ReservedMatrixTriple128 triple_;
  SwiftTruncation::TruncationPairs truncation_pairs_;
  SwiftHashVerifier::ReservedData verifier_received_hash_data_;
  SwiftHashVerifier::ReservedData verifier_s1_message_data_;
  SwiftHashVerifier::ReservedData verifier_s2_message_data_;
};

template<typename T>
class FpaMatrixMultiplicationConstantGate final : public OneGate {
  using Base = motion::OneGate;
 public:
  FpaMatrixMultiplicationConstantGate(swift::MatrixWirePointer<T> matrix_a, size_t constant);

  ~FpaMatrixMultiplicationConstantGate() final = default;

  FpaMatrixMultiplicationConstantGate(FpaMatrixMultiplicationConstantGate const&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

 private:
  size_t constant_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> matrix_multiply_future_online_;
  SwiftTruncation::TruncationPairs truncation_pairs_;
  SwiftHashVerifier::ReservedData verifier_received_hash_data_;
  SwiftHashVerifier::ReservedData verifier_s1_message_data_;
  SwiftHashVerifier::ReservedData verifier_s2_message_data_;
};

template<typename T>
class BitAGate final : public OneGate {
  using Base = motion::OneGate;
 public:
  BitAGate(BitMatrixWirePointer bit_matrix_wire);

  ~BitAGate() final = default;

  BitAGate(BitAGate const&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
 private:
  std::vector<boost::numeric::ublas::matrix<T>> H_my_id, H_previous_id;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> bit_a_future_setup_d_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> bit_a_future_setup_f_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> bit_a_future_online_;
  SwiftSacrificeVerifier::ReservedTriple128 triple_;
  SwiftHashVerifier::ReservedData verifier_received_hash_data_;
  SwiftHashVerifier::ReservedData verifier_s1_message_data_;
  SwiftHashVerifier::ReservedData verifier_s2_message_data_;
};

swift::BooleanWirePointer MsbAdd(std::vector<swift::BooleanWirePointer> const& a, 
                                 std::vector<swift::BooleanWirePointer> const& b);


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
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> msb_future_;
  std::vector<swift::BooleanWirePointer> A_, B_, C_;
  BooleanWirePointer PPA_;
  SwiftHashVerifier::ReservedData verifier_data_;
};

template<typename T>
swift::WirePointer<T> ReLU(
  boost::numeric::ublas::matrix<swift::WirePointer<T>> const& X) {
  using boost::numeric::ublas::matrix;
  
  Backend& backend = X(0, 0)->GetBackend();
  auto matrix_conversion_gate = 
    backend.GetRegister()->EmplaceGate<swift::MatrixConversionGate<T>>(X);
    
  auto matrix_conversion_wire = 
    std::dynamic_pointer_cast<swift::MatrixWire<T>>(
      matrix_conversion_gate->GetOutputWires()[0]);
      
  //The msb is already inverted, so we can skip step 2 and get C directly
  auto C_gate = 
    backend.GetRegister()->EmplaceGate<swift::MsbGate<T>>(matrix_conversion_wire);
  auto C_wire = 
    std::dynamic_pointer_cast<swift::BitMatrixWire>(C_gate->GetOutputWires()[0]);

  auto D_gate = backend.GetRegister()->EmplaceGate<swift::BitAGate<T>>(C_wire);
    auto D_wire =  
      std::dynamic_pointer_cast<swift::MatrixWire<T>>(D_gate->GetOutputWires()[0]);

  auto D_simd_reconversion_gate = 
    backend.GetRegister()->EmplaceGate<swift::MatrixSimdReconversionGate<T>>(D_wire);
  auto D_simd_wire = D_simd_reconversion_gate->GetWire();
  
  auto X_simd_reconversion_gate = 
    backend.GetRegister()->EmplaceGate<swift::MatrixSimdReconversionGate<T>>(matrix_conversion_wire);
  auto X_simd_wire = X_simd_reconversion_gate->GetWire();
  
  auto multiplication_gate =
    backend.GetRegister()->EmplaceGate<swift::MultiplicationGate<T>>(
      D_simd_wire, X_simd_wire);
  auto multiplication_wire = 
    std::dynamic_pointer_cast<swift::Wire<T>>(
      multiplication_gate->GetOutputWires()[0]);
    
  
  return multiplication_wire;
}
    
} //namespace encrypto::motion::proto::swift