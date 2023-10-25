#include "boolean_astra_wire.h"

namespace encrypto::motion::proto::boolean_astra {

Wire::Wire(Backend& backend, BitVector<> values, BitVector<> lambdas1, BitVector<> lambdas2)
  : Base(backend, values.GetSize()), values_{std::move(values)}, 
    lambdas1_{std::move(lambdas1)}, lambdas2_{std::move(lambdas2)}, 
    setup_ready_condition_{std::make_unique<FiberCondition>([this]() { return setup_ready_.load(); })} {
  assert(0 < values_.GetSize());      
  assert(lambdas1_.GetSize() == values_.GetSize());     
  assert(lambdas2_.GetSize() == values_.GetSize());     
}

BitMatrixWire::BitMatrixWire(Backend& backend, BitVector<> values, 
                             BitVector<> lambdas1, BitVector<> lambdas2,
                             size_t m, size_t n, size_t matrix_simd_values)
: Base(backend, std::move(values), std::move(lambdas1), std::move(lambdas2)),
  m_(m), n_(n), matrix_simd_values_(matrix_simd_values) {}
    
} // namespace encrypto::motion::proto::boolean_astra