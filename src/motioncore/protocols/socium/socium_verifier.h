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
#include "primitives/sharing_randomness_generator.h"
#include <boost/numeric/ublas/matrix.hpp>
#include "protocols/swift/swift_verifier.h"

namespace encrypto::motion {

class SociumSacrificeVerifier { 
 public:
  
  class ReservedTriple64 {
   public:
    ReservedTriple64() = default;
    ReservedTriple64(ReservedTriple64 const&) = default;
    ReservedTriple64(ReservedTriple64&&) = default;
    ReservedTriple64& operator=(ReservedTriple64 const&) = default;
    ReservedTriple64& operator=(ReservedTriple64&&) = default;
    
    ReservedTriple64(SociumSacrificeVerifier* sacrifice_verify, size_t offset);
    
    void AppendTriple(uint64_t lambda_i_x, uint64_t lambda_i_minus_1_x,
                      uint64_t lambda_i_y, uint64_t lambda_i_minus_1_y,
                      uint64_t gamma_i_xy, uint64_t gamma_i_minus_1_xy);
   private:
    SociumSacrificeVerifier* sacrifice_verify_;
    size_t offset_;
  };
  
  class ReservedTriple128 {
   public:
    ReservedTriple128() = default;
    ReservedTriple128(ReservedTriple128 const&) = default;
    ReservedTriple128(ReservedTriple128&&) = default;
    ReservedTriple128& operator=(ReservedTriple128 const&) = default;
    ReservedTriple128& operator=(ReservedTriple128&&) = default;
   
    ReservedTriple128(SociumSacrificeVerifier* sacrifice_verify, size_t offset);
    
    void AppendTriple(UInt128 lambda_i_x, UInt128 lambda_i_minus_1_x,
                      UInt128 lambda_i_y, UInt128 lambda_i_minus_1_y,
                      UInt128 gamma_i_xy, UInt128 gamma_i_minus_1_xy);
   private:
    SociumSacrificeVerifier* sacrifice_verify_;
    size_t offset_;
  };
  
  class ReservedMatrixTriple64 {
   public:
    ReservedMatrixTriple64() = default;
    ReservedMatrixTriple64(ReservedMatrixTriple64 const&) = default;
    ReservedMatrixTriple64(ReservedMatrixTriple64&&) = default;
    ReservedMatrixTriple64& operator=(ReservedMatrixTriple64 const&) = default;
    ReservedMatrixTriple64& operator=(ReservedMatrixTriple64&&) = default;
    
    ReservedMatrixTriple64(SociumSacrificeVerifier* sacrifice_verify, size_t offset);
    
    void AppendTriple(
      boost::numeric::ublas::matrix<uint64_t> lambda_i_x,
      boost::numeric::ublas::matrix<uint64_t> lambda_i_minus_1_x,
      boost::numeric::ublas::matrix<uint64_t> lambda_i_y, 
      boost::numeric::ublas::matrix<uint64_t> lambda_i_minus_1_y, 
      boost::numeric::ublas::matrix<uint64_t> gamma_i_xy,
      boost::numeric::ublas::matrix<uint64_t> gamma_i_minus_1_xy);
   private:
    SociumSacrificeVerifier* sacrifice_verify_;
    size_t offset_;
  };
  
  class ReservedMatrixTriple128 {
   public:
    ReservedMatrixTriple128() = default;
    ReservedMatrixTriple128(ReservedMatrixTriple128 const&) = default;
    ReservedMatrixTriple128(ReservedMatrixTriple128&&) = default;
    ReservedMatrixTriple128& operator=(ReservedMatrixTriple128 const&) = default;
    ReservedMatrixTriple128& operator=(ReservedMatrixTriple128&&) = default;
    
    ReservedMatrixTriple128(SociumSacrificeVerifier* sacrifice_verify, size_t offset);
    
    void AppendTriple(
      boost::numeric::ublas::matrix<UInt128> lambda_i_x,
      boost::numeric::ublas::matrix<UInt128> lambda_i_minus_1_x,
      boost::numeric::ublas::matrix<UInt128> lambda_i_y, 
      boost::numeric::ublas::matrix<UInt128> lambda_i_minus_1_y, 
      boost::numeric::ublas::matrix<UInt128> gamma_i_xy,
      boost::numeric::ublas::matrix<UInt128> gamma_i_minus_1_xy);
   private:
    SociumSacrificeVerifier* sacrifice_verify_;
    size_t offset_;
  };
  
  friend class ReservedTriple64;
  friend class ReservedTriple128;
  friend class ReservedMatrixTriple64;
  friend class ReservedMatrixTriple128;
  
  SociumSacrificeVerifier(Backend& backend);
  
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
  
  std::vector<uint64_t> lambdas_i_x64_, lambdas_i_y64_, gammas_i_xy64_;
  std::vector<uint64_t> lambdas_i_minus_1_x64_, lambdas_i_minus_1_y64_, gammas_i_minus_1_xy64_;
  std::vector<UInt128> lambdas_i_x128_, lambdas_i_y128_, gammas_i_xy128_;
  std::vector<UInt128> lambdas_i_minus_1_x128_, lambdas_i_minus_1_y128_, gammas_i_minus_1_xy128_;
  std::vector<boost::numeric::ublas::matrix<uint64_t>> 
    matrix_lambdas_i_x64_, matrix_lambdas_i_y64_, matrix_gammas_i_xy64_,
    matrix_lambdas_i_minus_1_x64_, matrix_lambdas_i_minus_1_y64_, matrix_gammas_i_minus_1_xy64_;
  std::vector<boost::numeric::ublas::matrix<UInt128>> 
    matrix_lambdas_i_x128_, matrix_lambdas_i_y128_, matrix_gammas_i_xy128_,
    matrix_lambdas_i_minus_1_x128_, matrix_lambdas_i_minus_1_y128_, matrix_gammas_i_minus_1_xy128_;
  
  motion::ReusableFiberFuture<std::vector<uint8_t>> 
    semi_mult_future_, v_future_, v_hash_future_, check_zero_future_;
};

using SociumHashVerifier = SwiftHashVerifier;

}  // namespace encrypto::motion