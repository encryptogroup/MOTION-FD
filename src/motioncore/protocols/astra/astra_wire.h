#pragma once

#include "protocols/wire.h"
#include "protocols/boolean_astra/boolean_astra_wire.h"
#include <boost/numeric/ublas/matrix.hpp>

namespace encrypto::motion::proto::astra {
    
template<typename T>
class Wire final : public motion::Wire {
  using Base = motion::Wire;
 public:
  // TODO: each party always has exactly 2 values. Store 2 elements?
  struct Data {
    Data() : value{}, lambda1{}, lambda2{} {}
    Data(T v, T l1, T l2) : value{v}, lambda1{l1}, lambda2{l2} {}
    T value;
    T lambda1;
    T lambda2;
  };

  using value_type = Data;
 
 Wire() = default;
 
  Wire(Backend& backend, std::vector<Data> values);
  Wire(Backend& backend, std::size_t number_of_simd);
  
  ~Wire() = default;
  
  MpcProtocol GetProtocol() const final { return MpcProtocol::kAstra; }
  
  CircuitType GetCircuitType() const final { return CircuitType::kArithmetic; }

  virtual bool IsConstant() const noexcept final { return false; };
  
  virtual std::size_t GetBitLength() const final { return sizeof(T) * 8; };
  
  const std::vector<Data>& GetValues() const { return values_; }
  
  std::vector<Data>& GetMutableValues() { return values_; }

  void SetSetupIsReady() {
    {
      std::scoped_lock lock(setup_ready_condition_->GetMutex());
      setup_ready_ = true;
    }
    setup_ready_condition_->NotifyAll();
  }

  const auto& GetSetupReadyCondition() const { return setup_ready_condition_; }
  
 private:
  std::vector<Data> values_;

  std::atomic<bool> setup_ready_{false};
  std::unique_ptr<FiberCondition> setup_ready_condition_;
};

template<typename T>
using WirePointer = std::shared_ptr<astra::Wire<T>>;

template<typename T>
class MatrixWire final : public motion::Wire {
  using Base = motion::Wire;
 public:
  MatrixWire(Backend& backend, size_t m, size_t n, size_t number_of_simd_values);
  
  MpcProtocol GetProtocol() const final { return MpcProtocol::kAstra; }
  
  CircuitType GetCircuitType() const final { return CircuitType::kArithmetic; }

  virtual bool IsConstant() const noexcept final { return false; };
  
  virtual std::size_t GetBitLength() const final { return sizeof(T) * 8; };

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
  
  std::vector<boost::numeric::ublas::matrix<T>>& GetMutableLambdaMatrices() {
    return lambda_matrices;
  }
  
  std::vector<boost::numeric::ublas::matrix<T>> const& GetValueMatrices() const {
    return value_matrices;
  }
  
  std::vector<boost::numeric::ublas::matrix<T>> const& GetLambdaMatrices() const {
    return lambda_matrices;
  }
  
 private:
 
  std::vector<boost::numeric::ublas::matrix<T>> value_matrices;
  std::vector<boost::numeric::ublas::matrix<T>> lambda_matrices;
  
  std::atomic<bool> setup_ready_{false};
  std::unique_ptr<FiberCondition> setup_ready_condition_;
};

template<typename T>
using MatrixWirePointer = std::shared_ptr<astra::MatrixWire<T>>;
    
} // namespace encrypto::motion::proto::astra