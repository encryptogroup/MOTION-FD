#pragma once

#include "base/backend.h"
#include "primitives/sharing_randomness_generator.h"
#include "utility/z2_integer.h"
#include <boost/numeric/ublas/matrix.hpp>

namespace encrypto::motion {

class AstraSacrificeVerifier {
    public:
  
  class ReservedTriple64 {
   public:
    ReservedTriple64() = default;
    ReservedTriple64(ReservedTriple64 const&) = default;
    ReservedTriple64(ReservedTriple64&&) = default;
    ReservedTriple64& operator=(ReservedTriple64 const&) = default;
    ReservedTriple64& operator=(ReservedTriple64&&) = default;
    
    ReservedTriple64(AstraSacrificeVerifier* sacrifice_verify, size_t offset);
    
    void AppendTriple(uint64_t lambda_x, uint64_t lambda_y, uint64_t gamma_xy);
   private:
    AstraSacrificeVerifier* sacrifice_verify_;
    size_t offset_;
  };
  
  class ReservedTriple128 {
   public:
    ReservedTriple128() = default;
    ReservedTriple128(ReservedTriple128 const&) = default;
    ReservedTriple128(ReservedTriple128&&) = default;
    ReservedTriple128& operator=(ReservedTriple128 const&) = default;
    ReservedTriple128& operator=(ReservedTriple128&&) = default;
   
    ReservedTriple128(AstraSacrificeVerifier* sacrifice_verify, size_t offset);
    
    void AppendTriple(UInt128 lambda_x, UInt128 lambda_y, UInt128 gamma_xy);
   private:
    AstraSacrificeVerifier* sacrifice_verify_;
    size_t offset_;
  };
  
  class ReservedMatrixTriple64 {
   public:
    ReservedMatrixTriple64() = default;
    ReservedMatrixTriple64(ReservedMatrixTriple64 const&) = default;
    ReservedMatrixTriple64(ReservedMatrixTriple64&&) = default;
    ReservedMatrixTriple64& operator=(ReservedMatrixTriple64 const&) = default;
    ReservedMatrixTriple64& operator=(ReservedMatrixTriple64&&) = default;
    
    ReservedMatrixTriple64(AstraSacrificeVerifier* sacrifice_verify, size_t offset);
    
    void AppendTriple(
      boost::numeric::ublas::matrix<uint64_t> lambda_x, 
      boost::numeric::ublas::matrix<uint64_t> lambda_y, 
      boost::numeric::ublas::matrix<uint64_t> gamma_xy);
   private:
    AstraSacrificeVerifier* sacrifice_verify_;
    size_t offset_;
  };
  
  class ReservedMatrixTriple128 {
   public:
    ReservedMatrixTriple128() = default;
    ReservedMatrixTriple128(ReservedMatrixTriple128 const&) = default;
    ReservedMatrixTriple128(ReservedMatrixTriple128&&) = default;
    ReservedMatrixTriple128& operator=(ReservedMatrixTriple128 const&) = default;
    ReservedMatrixTriple128& operator=(ReservedMatrixTriple128&&) = default;
    
    ReservedMatrixTriple128(AstraSacrificeVerifier* sacrifice_verify, size_t offset);
    
    void AppendTriple(
      boost::numeric::ublas::matrix<UInt128> lambda_x, 
      boost::numeric::ublas::matrix<UInt128> lambda_y, 
      boost::numeric::ublas::matrix<UInt128> gamma_xy);
   private:
    AstraSacrificeVerifier* sacrifice_verify_;
    size_t offset_;
  };
  
  friend class ReservedTriple64;
  friend class ReservedTriple128;
  friend class ReservedMatrixTriple64;
  friend class ReservedMatrixTriple128;
  
  AstraSacrificeVerifier(Backend& backend);
  
  ReservedTriple64 ReserveTriples64(size_t number_of_triples);
  ReservedTriple128 ReserveTriples128(size_t number_of_triples);
  ReservedMatrixTriple64 ReserveMatrixTriples64(size_t number_of_triples);
  ReservedMatrixTriple128 ReserveMatrixTriples128(size_t number_of_triples);
  
  void SetReady();
  const FiberCondition& GetIsReadyCondition() const noexcept { return check_is_done_condition_; }
  
  void Verify();
  
 private:
  Backend& backend_;
  size_t gate_id_;
  
  //dependencies starts with the value of 2´. Its value is increased every time a ReserveTriples*
  //method is invoked and decreased when SetReady() is invoked. When reaching a value of 1 Verify()
  //is called. The framework guarantees that SetReady() will be called exactly one more time than ReserveTriples*.
  std::atomic_size_t dependencies_;
  FiberCondition check_is_done_condition_;
  
  //The sacrifice triples for 64-bit and 128-bit resepctively. 
  //For S_0 the attributes contain lambdas_x, lambdas_y and gammas_xy
  //For S_1 the attributes contain lambdas1_x, lambdas1_y, gammas1_xy
  //For S_2 the attributes contain lambdas2_x, lambdas2_y, gammas2_xy
  std::vector<uint64_t> lambdas_x64_, lambdas_y64_, gammas_xy64_;
  std::vector<UInt128> lambdas_x128_, lambdas_y128_, gammas_xy128_;
  std::vector<boost::numeric::ublas::matrix<uint64_t>> 
    matrix_lambdas_x64_, matrix_lambdas_y64_, matrix_gammas_xy64_;
  std::vector<boost::numeric::ublas::matrix<UInt128>> 
    matrix_lambdas_x128_, matrix_lambdas_y128_, matrix_gammas_xy128_;
  
  motion::ReusableFiberFuture<std::vector<uint8_t>> 
    triple_future_p0_, triple_future_p1_p2_;
  
};

}  // namespace encrypto::motion