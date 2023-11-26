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

#include "protocols/wire.h"
#include <boost/numeric/ublas/matrix.hpp>
#include <vector>
#include <utility/bit_vector.h>

namespace encrypto::motion::proto::socium {
    
template<typename T>
class Wire : public motion::Wire {
  using Base = motion::Wire;
 public:
  struct Data {
    std::vector<T> values, lambda_my_id, lambda_previous_id;
  };
  
  using value_type = Data;
 
 Wire() = default;
 
  Wire(Backend& backend, size_t number_of_simd_values, 
       std::vector<T> values, std::vector<T> lambda_my_id, std::vector<T> lambda_previous_id);
  Wire(Backend& backend, size_t number_of_simd_values);
  
  ~Wire() = default;
  
  MpcProtocol GetProtocol() const { return MpcProtocol::kSocium; }
  
  CircuitType GetCircuitType() const { return CircuitType::kArithmetic; }

  virtual bool IsConstant() const noexcept { return false; };
  
  virtual std::size_t GetBitLength() const { return sizeof(T) * 8; };
  
  Data const& GetData() const { return data_; }
  
  Data& GetMutableData() { return data_; }

  void SetSetupIsReady() {
    {
      std::scoped_lock lock(setup_ready_condition_->GetMutex());
      setup_ready_ = true;
    }
    setup_ready_condition_->NotifyAll();
  }

  const auto& GetSetupReadyCondition() const { return setup_ready_condition_; }
  
 private:
  Data data_;

  std::atomic<bool> setup_ready_{false};
  std::unique_ptr<FiberCondition> setup_ready_condition_;
};

template<typename T>
using WirePointer = std::shared_ptr<socium::Wire<T>>;


template<typename T>
class MatrixWire : public motion::Wire {
  using Base = motion::Wire;
 public:
  MatrixWire(Backend& backend, size_t m, size_t n, size_t number_of_simd_values);
  
  MpcProtocol GetProtocol() const { return MpcProtocol::kSocium; }
  
  CircuitType GetCircuitType() const { return CircuitType::kArithmetic; }

  virtual bool IsConstant() const noexcept { return false; };
  
  virtual std::size_t GetBitLength() const { return sizeof(T) * 8; };

  void SetSetupIsReady() {
    {
      std::scoped_lock lock(setup_ready_condition_->GetMutex());
      setup_ready_ = true;
    }
    setup_ready_condition_->NotifyAll();
  }
  
  const auto& GetSetupReadyCondition() const { return setup_ready_condition_; }
  
  std::vector<boost::numeric::ublas::matrix<T>>& GetMutableValueMatrices() {
    return value_matrices;
  }
  
  std::vector<boost::numeric::ublas::matrix<T>>& GetMutableLambdaMyIdMatrices() {
    return lambda_my_id_matrices;
  }
  
  std::vector<boost::numeric::ublas::matrix<T>>& GetMutableLambdaPreviousIdMatrices() {
    return lambda_previous_id_matrices;
  }
  
 private:
 
  std::vector<boost::numeric::ublas::matrix<T>> value_matrices;
  std::vector<boost::numeric::ublas::matrix<T>> lambda_my_id_matrices;
  std::vector<boost::numeric::ublas::matrix<T>> lambda_previous_id_matrices;
  
  std::atomic<bool> setup_ready_{false};
  std::unique_ptr<FiberCondition> setup_ready_condition_;
};

template<typename T>
using MatrixWirePointer = std::shared_ptr<socium::MatrixWire<T>>;

class BooleanWire : public motion::BooleanWire {
  using Base = motion::BooleanWire;
 public:
 
  BooleanWire() = default;
 
  BooleanWire(
    Backend& backend, BitVector<> values, 
    BitVector<> lambdas_my_id, BitVector<> lambdas_previous_id);
  
  ~BooleanWire() = default;
  
  MpcProtocol GetProtocol() const { return MpcProtocol::kSocium; }

  virtual bool IsConstant() const noexcept { return false; };
  
  virtual std::size_t GetBitLength() const { return 1; };
  
  BitVector<> const& GetValues() const { return values_; }
  
  BitVector<>& GetMutableValues() { return values_; }
  
  BitVector<> const& GetLambdasMyId() const { return lambdas_my_id_; }
  
  BitVector<> const& GetLambdasPreviousId() const { return lambdas_previous_id_; }
  
  BitVector<>& GetMutableLambdasMyId() { return lambdas_my_id_; }
  
  BitVector<>& GetMutableLambdasPreviousId() { return lambdas_previous_id_; }

  void SetSetupIsReady() {
    {
      std::scoped_lock lock(setup_ready_condition_->GetMutex());
      setup_ready_ = true;
    }
    setup_ready_condition_->NotifyAll();
  }

  const auto& GetSetupReadyCondition() const { return setup_ready_condition_; }
  
 private:
  BitVector<> values_;
  BitVector<> lambdas_my_id_;
  BitVector<> lambdas_previous_id_;

  std::atomic<bool> setup_ready_{false};
  std::unique_ptr<FiberCondition> setup_ready_condition_;
};

using BooleanWirePointer = std::shared_ptr<BooleanWire>;

class BitMatrixWire : public socium::BooleanWire {
  using Base = socium::BooleanWire;
 public:

  BitMatrixWire(
    Backend& backend, BitVector<> values, 
    BitVector<> lambdas_my_id, BitVector<> lambdas_previous_id, 
    size_t m, size_t n, size_t matrix_simd_values);
  
  size_t GetNumberOfRows() const { return m_; }
  
  size_t GetNumberOfColumns() const { return n_; }
  
  size_t GetMatrixSimdValues() const { return matrix_simd_values_; }
  
 private:
  size_t  m_, n_, matrix_simd_values_;
};

using BitMatrixWirePointer = std::shared_ptr<BitMatrixWire>;

    
}  // namespace encrypto::motion::proto::socium