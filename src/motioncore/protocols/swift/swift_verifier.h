#pragma once

#include "base/backend.h"
#include "primitives/sharing_randomness_generator.h"
#include <boost/numeric/ublas/matrix.hpp>

namespace encrypto::motion {

class SwiftHashVerifier {
 public:
 
  struct ReservedData {
    template<typename T>
    void AssignData(std::vector<T> const& other_data) {
      uint8_t const* other_data_bytes = reinterpret_cast<uint8_t const*>(other_data.data());
      std::copy(other_data_bytes, other_data_bytes + other_data.size() * sizeof(T), data->data() + offset);
    }
    template<typename T>
    void AssignData(std::span<T> const& other_data) {
      uint8_t const* other_data_bytes = reinterpret_cast<uint8_t const*>(other_data.data());
      std::copy(other_data_bytes, other_data_bytes + other_data.size() * sizeof(T), data->data() + offset);
    }
    template<typename T>
    void AssignData(std::vector<boost::numeric::ublas::matrix<T>> const& other_data) {
      size_t data_offset = 0;
      for(size_t s = 0; s != other_data.size(); ++s) {
        size_t u = other_data[s].size1();
        size_t v = other_data[s].size2();
        for(size_t i = 0; i != u; ++i) {
          for(size_t j = 0; j != v; ++j) {
            T val = other_data[s](i, j);
            memcpy(data->data() + offset + data_offset, &val, sizeof(T));
            data_offset += sizeof(T);
          }
        }
      }
    }
    
    std::vector<uint8_t>* data;
    size_t offset;      
  };
  
  SwiftHashVerifier(Backend& backend);
  
  ReservedData ReserveHashMessage(size_t number_of_hash_bytes, uint64_t other_id);
  ReservedData ReserveHashCheck(size_t number_of_hash_bytes, uint64_t other_id);
  void SetReady();
  const FiberCondition& GetIsReadyCondition() const noexcept { return check_is_done_condition_; }
  
  void SendHash();
  void CheckHash();
  
 private:
  Backend& backend_;
  size_t gate_id_;
  
  //Hash inputs for previous_id and next_id. The hash inputs for previous_id or next_id
  //will be hashed during CheckHash and sent to previous_id or next_id when calling CheckHash
  std::array<std::vector<uint8_t>, 2> hash_messages_;
  //Hash datas that will be checked against hash received from previous_id or next_id 
  std::array<std::vector<uint8_t>, 2> hash_checks_;
  //Hash futures received from previous_id or next_id 
  std::array<motion::ReusableFiberFuture<std::vector<uint8_t>>, 2> hash_message_futures_;
  
  std::atomic<size_t> dependencies_;
  FiberCondition check_is_done_condition_;
};

class SwiftSacrificeVerifier {
    public:
  
  class ReservedTriple64 {
   public:
    ReservedTriple64() = default;
    ReservedTriple64(ReservedTriple64 const&) = default;
    ReservedTriple64(ReservedTriple64&&) = default;
    ReservedTriple64& operator=(ReservedTriple64 const&) = default;
    ReservedTriple64& operator=(ReservedTriple64&&) = default;
    
    ReservedTriple64(SwiftSacrificeVerifier* sacrifice_verify, size_t offset);
    
    void AppendTriple(uint64_t lambda_i_x, uint64_t lambda_i_minus_1_x,
                      uint64_t lambda_i_y, uint64_t lambda_i_minus_1_y,
                      uint64_t gamma_i_xy, uint64_t gamma_i_minus_1_xy);
   private:
    SwiftSacrificeVerifier* sacrifice_verify_;
    size_t offset_;
  };
  
  class ReservedTriple128 {
   public:
    ReservedTriple128() = default;
    ReservedTriple128(ReservedTriple128 const&) = default;
    ReservedTriple128(ReservedTriple128&&) = default;
    ReservedTriple128& operator=(ReservedTriple128 const&) = default;
    ReservedTriple128& operator=(ReservedTriple128&&) = default;
   
    ReservedTriple128(SwiftSacrificeVerifier* sacrifice_verify, size_t offset);
    
    void AppendTriple(UInt128 lambda_i_x, UInt128 lambda_i_minus_1_x,
                      UInt128 lambda_i_y, UInt128 lambda_i_minus_1_y,
                      UInt128 gamma_i_xy, UInt128 gamma_i_minus_1_xy);
   private:
    SwiftSacrificeVerifier* sacrifice_verify_;
    size_t offset_;
  };
  
  class ReservedMatrixTriple64 {
   public:
    ReservedMatrixTriple64() = default;
    ReservedMatrixTriple64(ReservedMatrixTriple64 const&) = default;
    ReservedMatrixTriple64(ReservedMatrixTriple64&&) = default;
    ReservedMatrixTriple64& operator=(ReservedMatrixTriple64 const&) = default;
    ReservedMatrixTriple64& operator=(ReservedMatrixTriple64&&) = default;
    
    ReservedMatrixTriple64(SwiftSacrificeVerifier* sacrifice_verify, size_t offset);
    
    void AppendTriple(
      boost::numeric::ublas::matrix<uint64_t> lambda_i_x,
      boost::numeric::ublas::matrix<uint64_t> lambda_i_minus_1_x,
      boost::numeric::ublas::matrix<uint64_t> lambda_i_y, 
      boost::numeric::ublas::matrix<uint64_t> lambda_i_minus_1_y, 
      boost::numeric::ublas::matrix<uint64_t> gamma_i_xy,
      boost::numeric::ublas::matrix<uint64_t> gamma_i_minus_1_xy);
   private:
    SwiftSacrificeVerifier* sacrifice_verify_;
    size_t offset_;
  };
  
  class ReservedMatrixTriple128 {
   public:
    ReservedMatrixTriple128() = default;
    ReservedMatrixTriple128(ReservedMatrixTriple128 const&) = default;
    ReservedMatrixTriple128(ReservedMatrixTriple128&&) = default;
    ReservedMatrixTriple128& operator=(ReservedMatrixTriple128 const&) = default;
    ReservedMatrixTriple128& operator=(ReservedMatrixTriple128&&) = default;
    
    ReservedMatrixTriple128(SwiftSacrificeVerifier* sacrifice_verify, size_t offset);
    
    void AppendTriple(
      boost::numeric::ublas::matrix<UInt128> lambda_i_x,
      boost::numeric::ublas::matrix<UInt128> lambda_i_minus_1_x,
      boost::numeric::ublas::matrix<UInt128> lambda_i_y, 
      boost::numeric::ublas::matrix<UInt128> lambda_i_minus_1_y, 
      boost::numeric::ublas::matrix<UInt128> gamma_i_xy,
      boost::numeric::ublas::matrix<UInt128> gamma_i_minus_1_xy);
   private:
    SwiftSacrificeVerifier* sacrifice_verify_;
    size_t offset_;
  };
  
  friend class ReservedTriple64;
  friend class ReservedTriple128;
  friend class ReservedMatrixTriple64;
  friend class ReservedMatrixTriple128;
  
  SwiftSacrificeVerifier(Backend& backend);
  
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
    semi_mult_future_, r_future_, r_hash_future_, v_future_, v_hash_future_, 
    previous_id_check_zero_future_, next_id_check_zero_future_;
  
};

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

}  // namespace encrypto::motion