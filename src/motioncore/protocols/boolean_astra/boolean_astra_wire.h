#pragma once

#include "protocols/wire.h"
#include "utility/bit_vector.h"

namespace encrypto::motion::proto::boolean_astra {
    
class Wire : public motion::BooleanWire {
  using Base = motion::BooleanWire;
 public:
 
  Wire() = default;
 
  Wire(Backend& backend, BitVector<> values, BitVector<> lambdas1, BitVector<> lambdas2);
  
  ~Wire() = default;
  
  MpcProtocol GetProtocol() const final { return MpcProtocol::kBooleanAstra; }

  virtual bool IsConstant() const noexcept final { return false; };
  
  virtual std::size_t GetBitLength() const final { return 1; };
  
  BitVector<> const& GetValues() const { return values_; }
  
  BitVector<>& GetMutableValues() { return values_; }
  
  BitVector<> const& GetLambdas1() const { return lambdas1_; }
  
  BitVector<> const& GetLambdas2() const { return lambdas2_; }
  
  BitVector<>& GetMutableLambdas1() { return lambdas1_; }
  
  BitVector<>& GetMutableLambdas2() { return lambdas2_; }

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
  BitVector<> lambdas1_;
  BitVector<> lambdas2_;

  std::atomic<bool> setup_ready_{false};
  std::unique_ptr<FiberCondition> setup_ready_condition_;
};

using WirePointer = std::shared_ptr<boolean_astra::Wire>;

class BitMatrixWire final : public boolean_astra::Wire {
  using Base = boolean_astra::Wire;
    public:

  BitMatrixWire(Backend& backend, BitVector<> values, 
                BitVector<> lambdas1, BitVector<> lambdas2, 
                size_t m, size_t n, size_t matrix_simd_values);
  
  size_t GetNumberOfRows() const { return m_; }
  
  size_t GetNumberOfColumns() const { return n_; }
  
  size_t GetMatrixSimdValues() const { return matrix_simd_values_; }
  
 private:
  size_t  m_, n_, matrix_simd_values_;
};

using BitMatrixWirePointer = std::shared_ptr<BitMatrixWire>;
    
} // namespace encrypto::motion::proto::boolean_astra