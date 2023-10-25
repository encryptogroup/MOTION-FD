#pragma once

#include "base/backend.h"
#include "communication/message.h"
#include "primitives/sharing_randomness_generator.h"
#include <boost/numeric/ublas/matrix.hpp>

#include "swift_verifier.h"

namespace encrypto::motion {

class SwiftTruncation {
 public:
  
  SwiftTruncation(Backend& backend, size_t d);
  
  void InitializeRandom();
  
  void GenerateR();
  
  void GenerateRd();
  
 private:
  Backend& backend_;
  size_t d_, gate_id_, r_gate_id_, rd_gate_id_;
  
  size_t number_of_truncation_pairs_ = 0;
  std::vector<uint64_t> 
    rs_my_id_, rs_previous_id_, rds_my_id_, rds_previous_id_;
  std::vector<uint8_t> randoms1_, randoms2_;
  std::atomic<bool> r_done_ = false, rd_done_ = false;
  FiberCondition r_done_condition_, rd_done_condition_;
  ReusableFiberFuture<std::vector<uint8_t>> future_r_, future_rd_;
  SwiftSacrificeVerifier::ReservedMatrixTriple128 triple_r_, triple_rd_;
  
  
  std::pair<std::vector<uint64_t>, std::vector<uint64_t>>  DotProduct(
  std::vector<uint64_t> const& A_my_id, std::vector<uint64_t> const& A_previous_id,
  std::vector<uint64_t> const& B_my_id, std::vector<uint64_t> const& B_previous_id,
  size_t id, SwiftSacrificeVerifier::ReservedMatrixTriple128& triple,
  ReusableFiberFuture<std::vector<uint8_t>>& future,
  communication::MessageType message_type);
  
 public:
  class TruncationPairs {
   public:
    TruncationPairs(SwiftTruncation const* truncation, size_t offset, size_t number_of_pairs)
    : truncation_(truncation), offset_(offset), number_of_pairs_(number_of_pairs) {}
    
    std::span<uint64_t const> GetRsMyId() {
      return {truncation_->rs_my_id_.data() + offset_, number_of_pairs_};
    }
    
    std::span<uint64_t const> GetRsPreviousId() {
      return {truncation_->rs_previous_id_.data() + offset_, number_of_pairs_};
    }
    
    std::span<uint64_t const> GetRdsMyId() {
      return {truncation_->rds_my_id_.data() + offset_, number_of_pairs_};
    }
    
    std::span<uint64_t const> GetRdsPreviousId() {
      return {truncation_->rds_previous_id_.data() + offset_, number_of_pairs_};
    }
    
   private:
    SwiftTruncation const* truncation_;
    size_t offset_;
    size_t number_of_pairs_;
  };
  
  friend TruncationPairs;
  
  FiberCondition const& GetRIsReadyCondition() const noexcept { 
    return r_done_condition_; 
  }
  
  FiberCondition const& GetRDIsReadyCondition() const noexcept { 
    return rd_done_condition_; 
  }
  
  TruncationPairs AddTruncationPairs(size_t number_of_pairs) {
    size_t offset = number_of_truncation_pairs_;
    number_of_truncation_pairs_ += number_of_pairs;
    return {this, offset, number_of_pairs};
  }
  
  FiberCondition& GetRDoneCondition() {
    return r_done_condition_;
  }
  
  FiberCondition& GetRDDoneCondition() {
    return rd_done_condition_;
  }
  
};

}  // namespace encrypto::motion