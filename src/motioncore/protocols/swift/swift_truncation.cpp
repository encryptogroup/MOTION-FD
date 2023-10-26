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

#include "base/backend.h"
#include "primitives/blake2b.h"
#include "communication/message_manager.h"

#include <utility>

#include "swift_truncation.h"

using namespace std::string_literals;
namespace {
    
std::mutex print_mutex;

[[maybe_unused]] void print_line(std::string str) {
  std::scoped_lock lock{print_mutex};
  std::cout << str << std::endl;
}

[[maybe_unused]] void print_line(std::string str, auto&& msg) {
  std::scoped_lock lock{print_mutex};
  std::cout << str << msg << std::endl;
}

}

namespace encrypto::motion {
using std::to_string;

SwiftTruncation::SwiftTruncation(Backend& backend, size_t d)
: backend_(backend), d_(d),
  gate_id_{backend.GetRegister()->NextGateId()},
  r_gate_id_{backend.GetRegister()->NextGateId()},
  rd_gate_id_{backend.GetRegister()->NextGateId()},
  r_done_condition_([this](){ return r_done_.load(); }),
  rd_done_condition_([this](){ return rd_done_.load(); }) {
  using communication::MessageType::kSwiftTruncationR;
  using communication::MessageType::kSwiftTruncationRd;
  auto& communication_layer = backend_.GetCommunicationLayer();
  auto& message_manager = communication_layer.GetMessageManager();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t previous_id = (my_id + 2) % 3;
  
  future_r_ = 
    message_manager.RegisterReceive(previous_id, kSwiftTruncationR, gate_id_);
  future_rd_ = 
    message_manager.RegisterReceive(previous_id, kSwiftTruncationRd, gate_id_);
}

void SwiftTruncation::InitializeRandom() {
  auto& communication_layer = backend_.GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  
  if(number_of_truncation_pairs_ == 0) return;
  
  switch(my_id) {
    case 0: {
      auto& rng2 = backend_.GetBaseProvider().GetMyRandomnessGenerator(2);
      randoms2_ = 
        rng2.template GetUnsigned<uint8_t>(
          gate_id_, number_of_truncation_pairs_ * sizeof(uint64_t));
      break;
    }
    case 1: {
      auto& rng1 = backend_.GetBaseProvider().GetMyRandomnessGenerator(2);
      randoms1_ = 
        rng1.template GetUnsigned<uint8_t>(
          gate_id_, number_of_truncation_pairs_ * sizeof(uint64_t));
      break;
    }
    case 2: {
      auto& rng1 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(1);
      randoms1_ = 
        rng1.template GetUnsigned<uint8_t>(
          gate_id_, number_of_truncation_pairs_ * sizeof(uint64_t));
      
      auto& rng2 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(0);
      randoms2_ = 
        rng2.template GetUnsigned<uint8_t>(
          gate_id_, number_of_truncation_pairs_ * sizeof(uint64_t));
      break;
    }
  }
  
  rs_my_id_.resize(number_of_truncation_pairs_, 0);
  rs_previous_id_.resize(number_of_truncation_pairs_, 0);
  rds_my_id_.resize(number_of_truncation_pairs_, 0);
  rds_previous_id_.resize(number_of_truncation_pairs_, 0);
  triple_r_ = backend_.GetSwiftVerifier()->ReserveMatrixTriples128(number_of_truncation_pairs_);
  triple_rd_ = backend_.GetSwiftVerifier()->ReserveMatrixTriples128(number_of_truncation_pairs_);
}

std::pair<std::vector<uint64_t>, std::vector<uint64_t>> SwiftTruncation::DotProduct(
  std::vector<uint64_t> const& A_my_id, std::vector<uint64_t> const& A_previous_id,
  std::vector<uint64_t> const& B_my_id, std::vector<uint64_t> const& B_previous_id,
  size_t id, SwiftSacrificeVerifier::ReservedMatrixTriple128& triple,
  ReusableFiberFuture<std::vector<uint8_t>>& future,
  communication::MessageType message_type) {
  using boost::numeric::ublas::matrix;
                        
  size_t const dimension = A_my_id.size() / number_of_truncation_pairs_;
  assert(A_my_id.size() == number_of_truncation_pairs_ * dimension);
  assert(A_previous_id.size() == number_of_truncation_pairs_ * dimension);
  assert(B_my_id.size() == number_of_truncation_pairs_ * dimension);
  assert(B_previous_id.size() == number_of_truncation_pairs_ * dimension);
  
  auto& communication_layer = backend_.GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  
  size_t const random_bytes = number_of_truncation_pairs_ * sizeof(UInt128);
  
  //We assume the role of S_i and generate the random numbers we share with S_i+1
  auto& rng_i = backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
  //We assume the role of S_i+1 and generate the random numbers we share with S_i
  auto& rng_i_minus_1 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
  
  std::vector<uint8_t> alphas_my_id = 
    rng_i.template GetUnsigned<uint8_t>(id, random_bytes);
  //randoms_previous_id contains gamma_xy_previous_id followed by lambda_z_previous_id
  std::vector<uint8_t> alphas_previous_id = 
    rng_i_minus_1.template GetUnsigned<uint8_t>(id, random_bytes);
  
  {
    size_t offset = 0;
    uint8_t const* const alpha_i_pointer = alphas_my_id.data();
    uint8_t const* const alpha_i_minus_1_pointer = alphas_previous_id.data();
    uint8_t* const c_i_pointer = alphas_my_id.data();
    for(size_t s = 0; s != number_of_truncation_pairs_; ++s) {
      UInt128 alpha_i, alpha_i_minus_1;
      memcpy(&alpha_i, alpha_i_pointer + offset, sizeof(UInt128));
      memcpy(&alpha_i_minus_1, alpha_i_minus_1_pointer + offset, sizeof(UInt128));
      UInt128 c_i = 0;
      for(size_t i = 0; i != dimension; ++i) {
        c_i += A_my_id[dimension * s + i] * B_my_id[dimension * s + i] 
               + A_my_id[dimension * s + i] * B_previous_id[dimension * s + i]
               + A_previous_id[dimension * s + i] * B_my_id[dimension * s + i];
      }
      c_i += alpha_i - alpha_i_minus_1;
      memcpy(c_i_pointer + offset, &c_i, sizeof(UInt128));
      offset += sizeof(UInt128);
    }
    assert(offset == number_of_truncation_pairs_ * sizeof(UInt128));
  }
  //c_i are in alphas_my_id
  
  {
    auto payload = 
      std::span<uint8_t const>(
        alphas_my_id.data(), number_of_truncation_pairs_ * sizeof(UInt128));
    auto message = communication::BuildMessage(message_type, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  
  std::pair<std::vector<uint64_t>, std::vector<uint64_t>> result;
  result.first.reserve(number_of_truncation_pairs_);
  result.second.reserve(number_of_truncation_pairs_);
  {
    auto message = future.get();
    const auto payload = communication::GetMessage(message.data())->payload();
    auto received_data = std::span<uint8_t const>{payload->Data(), payload->size()};
    {
      size_t offset = 0;
      uint8_t const* const gamma_xy_my_id_pointer = alphas_my_id.data();
      uint8_t const* const gamma_xy_previous_id_pointer = received_data.data();
      for(size_t s = 0; s != number_of_truncation_pairs_; ++s) {
        UInt128 gamma_xy_my_id, gamma_xy_previous_id;
        memcpy(&gamma_xy_my_id, gamma_xy_my_id_pointer + offset, sizeof(UInt128));
        memcpy(&gamma_xy_previous_id, gamma_xy_previous_id_pointer + offset, sizeof(UInt128));

        // Need to set up matrices for sacrifice check
        matrix<UInt128> A_my_id_mat(1, dimension);
        matrix<UInt128> A_previous_id_mat(1, dimension);
        matrix<UInt128> B_my_id_mat(dimension, 1);
        matrix<UInt128> B_previous_id_mat(dimension, 1);
        matrix<UInt128> gamma_xy_my_id_mat(1, 1);
        matrix<UInt128> gamma_xy_previous_id_mat(1, 1);
        for(size_t i = 0; i != dimension; ++i) {
          A_my_id_mat(0, i) = A_my_id[dimension * s + i];
          A_previous_id_mat(0, i) = A_previous_id[dimension * s + i];
          B_my_id_mat(i, 0) = B_my_id[dimension * s + i];
          B_previous_id_mat(i, 0) = B_previous_id[dimension * s + i];
        }
        gamma_xy_my_id_mat(0, 0) = gamma_xy_my_id;
        gamma_xy_previous_id_mat(0, 0) = gamma_xy_previous_id;

        triple.AppendTriple(
          A_my_id_mat, A_previous_id_mat, 
          B_my_id_mat, B_previous_id_mat,
          gamma_xy_my_id_mat, gamma_xy_previous_id_mat);
        result.first.emplace_back(uint64_t(gamma_xy_my_id));
        result.second.emplace_back(uint64_t(gamma_xy_previous_id));
        offset += sizeof(UInt128);
      }
      assert(offset == number_of_truncation_pairs_ * sizeof(UInt128));
      backend_.GetSwiftVerifier()->SetReady();
    }
  }
  return result;
}

void SwiftTruncation::GenerateR() {
  using communication::MessageType::kSwiftTruncationR;
  size_t constexpr kL = sizeof(uint64_t) * CHAR_BIT;
  if(number_of_truncation_pairs_ == 0) return;
  
  auto& communication_layer = backend_.GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  
  std::vector<uint64_t> A_my_id(kL * number_of_truncation_pairs_), 
                        A_previous_id(kL * number_of_truncation_pairs_),
                        B_my_id(kL * number_of_truncation_pairs_), 
                        B_previous_id(kL * number_of_truncation_pairs_);
  
  {
    size_t offset = 0;
    uint8_t const* const randoms1_pointer = randoms1_.data(); 
    uint8_t const* const randoms2_pointer = randoms2_.data(); 
    for(size_t s = 0; s != number_of_truncation_pairs_; ++s) {
      uint64_t r_s_1 = 0, r_s_2 = 0;
      switch(my_id) {
        case 0: {
          assert(randoms1_.size() == 0);
          assert(randoms2_.size() == number_of_truncation_pairs_ * sizeof(uint64_t));
          r_s_1 = 0;
          memcpy(&r_s_2, randoms2_pointer + offset, sizeof(uint64_t));
          break;
        }
        case 1: {
          assert(randoms1_.size() == number_of_truncation_pairs_ * sizeof(uint64_t));
          assert(randoms2_.size() == 0);
          memcpy(&r_s_1, randoms1_pointer + offset, sizeof(uint64_t));
          r_s_2 = 0;
          break;
        }
        case 2: {
          assert(randoms1_.size() == number_of_truncation_pairs_ * sizeof(uint64_t));
          assert(randoms2_.size() == number_of_truncation_pairs_ * sizeof(uint64_t));
          memcpy(&r_s_1, randoms1_pointer + offset, sizeof(uint64_t));
          memcpy(&r_s_2, randoms2_pointer + offset, sizeof(uint64_t));
          break;
        }
      }
      for(size_t i = 0; i != kL; ++i) {
        size_t const index = s * kL + i;
        switch(my_id) {
          case 0: {
            A_previous_id[index] = 0;
            A_my_id[index] = 0;
            //We select the i-th bit of r_s_2 <r_2,i>
            B_previous_id[index] = (r_s_2 >> i) & 0x1;
            B_my_id[index] = 0;
            break;
          }
          case 1: {
            A_previous_id[index] = 0;
            //We select the i-th bit of r_s_1 and shift it by i+1 (2^(i+1) * <r_1,i>)
            A_my_id[index] = (r_s_1 & (0x1 << i)) << 1;
            B_previous_id[index] = 0;
            B_my_id[index] = 0;
            break;
          }
          case 2: {
            //We select the i-th bit of r_s_1 and shift it by i+1 (2^(i+1) * <r_1,i>)
            A_previous_id[index] = (r_s_1 & (0x1 << i)) << 1;
            A_my_id[index] = 0;
            B_previous_id[index] = 0;
            //We select the i-th bit of r_s_2 <r_2,i>
            B_my_id[index] = (r_s_2 >> i) & 0x1;
            break;
          }
        }
      }
      offset += sizeof(uint64_t);
    }
    assert(offset == number_of_truncation_pairs_ * sizeof(uint64_t));
  }
  
  std::pair<std::vector<uint64_t>, std::vector<uint64_t>> x = 
    DotProduct(A_my_id, A_previous_id, B_my_id, B_previous_id, 
               r_gate_id_, triple_r_, future_r_, kSwiftTruncationR);
  
  for(size_t s = 0; s != number_of_truncation_pairs_; ++s) {
    for(size_t i = 0; i != kL; ++i) {
      size_t const index = s * kL + i;
      //A_my_id[index] is 2^(i+1) * <r_1,i> and B_my_id[index] is <r_2,i>
      rs_my_id_[s] += (A_my_id[index] >> 1) + (B_my_id[index] << i);
      rs_previous_id_[s] += (A_previous_id[index] >> 1) + (B_previous_id[index] << i);
      
    }
    rs_my_id_[s] -= x.first[s];
    rs_previous_id_[s] -= x.second[s];
  }
  
  r_done_ = true;
  r_done_condition_.NotifyAll();
}

void SwiftTruncation::GenerateRd() {
  using communication::MessageType::kSwiftTruncationRd;
  size_t constexpr kL = sizeof(uint64_t) * CHAR_BIT;
  if(number_of_truncation_pairs_ == 0) return;
  
  
  auto& communication_layer = backend_.GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  
  assert(d_ < kL);
  size_t const f = d_;
  size_t const l_minus_f = kL - f;
  size_t mask = 0;
  //mask is equal to sigma_{i = l-f}^{l}(2^i)
  mask = (~mask) << l_minus_f;
  
  std::vector<uint64_t> C_my_id(l_minus_f * number_of_truncation_pairs_), 
                        C_previous_id(l_minus_f * number_of_truncation_pairs_),
                        D_my_id(l_minus_f * number_of_truncation_pairs_), 
                        D_previous_id(l_minus_f * number_of_truncation_pairs_);
  
  {
    size_t offset = 0;
    uint8_t const* const randoms1_pointer = randoms1_.data(); 
    uint8_t const* const randoms2_pointer = randoms2_.data(); 
    for(size_t s = 0; s != number_of_truncation_pairs_; ++s) {
      uint64_t r_s_1 = 0, r_s_2 = 0;
      switch(my_id) {
        case 0: {
          assert(randoms1_.size() == 0);
          assert(randoms2_.size() == number_of_truncation_pairs_ * sizeof(uint64_t));
          r_s_1 = 0;
          memcpy(&r_s_2, randoms2_pointer + offset, sizeof(uint64_t));
          break;
        }
        case 1: {
          assert(randoms1_.size() == number_of_truncation_pairs_ * sizeof(uint64_t));
          assert(randoms2_.size() == 0);
          memcpy(&r_s_1, randoms1_pointer + offset, sizeof(uint64_t));
          r_s_2 = 0;
          break;
        }
        case 2: {
          assert(randoms1_.size() == number_of_truncation_pairs_ * sizeof(uint64_t));
          assert(randoms2_.size() == number_of_truncation_pairs_ * sizeof(uint64_t));
          memcpy(&r_s_1, randoms1_pointer + offset, sizeof(uint64_t));
          memcpy(&r_s_2, randoms2_pointer + offset, sizeof(uint64_t));
          break;
        }
      }
      for(size_t i = 0; i != l_minus_f; ++i) {
        size_t const index = s * l_minus_f + i;
        switch(my_id) {
          case 0: {
            C_previous_id[index] = 0;
            C_my_id[index] = 0;
            //We select the f+i-th bit of r_s_2 <r_2,f+i>
            D_previous_id[index] = (r_s_2 >> (f + i)) & 0x1;
            D_my_id[index] = 0;
            break;
          }
          case 1: {
            C_previous_id[index] = 0;
            //We select the f+i-th bit of r_s_1 and shift it by i+1 (2^(i+1) * <r_1,f+i>)
            C_my_id[index] = ((r_s_1 >> (f + i)) & 0x1) << (i+1);
            D_previous_id[index] = 0;
            D_my_id[index] = 0;
            break;
          }
          case 2: {
            //We select the f+i-th bit of r_s_1 and shift it by i+1 (2^(i+1) * <r_1,f+i>)
            C_previous_id[index] = ((r_s_1 >> (f + i)) & 0x1) << (i+1);
            C_my_id[index] = 0;
            D_previous_id[index] = 0;
            //We select the f+i-th bit of r_s_2 <r_2,f+i>
            D_my_id[index] = (r_s_2 >> (f + i)) & 0x1;
            break;
          }
        }
      }
      size_t const index = s*l_minus_f + l_minus_f - 1;
      switch(my_id) {
        case 0: {
          C_previous_id[index] = 0;
          C_my_id[index] = 0;
          break;
        }
        case 1: {
          C_previous_id[index] = 0;
          C_my_id[index] = mask * ((r_s_1 >> (kL - 1)) & 0x1);
          break;
        }
        case 2: {
          C_previous_id[index] = mask * ((r_s_1 >> (kL - 1)) & 0x1);
          C_my_id[index] = 0;
          break;
        }
      }
      
      offset += sizeof(uint64_t);
    }
    assert(offset == number_of_truncation_pairs_ * sizeof(uint64_t));
  }
  
  std::pair<std::vector<uint64_t>, std::vector<uint64_t>> y = 
    DotProduct(C_my_id, C_previous_id, D_my_id, D_previous_id, 
               rd_gate_id_, triple_rd_, future_rd_, kSwiftTruncationRd);
  
  for(size_t s = 0; s != number_of_truncation_pairs_; ++s) {
    for(size_t i = 0; i != l_minus_f; ++i) {
      size_t const index = s * l_minus_f + i;
      //C_my_id[index] is 2^(i+1) * <r_1,f+i> and D_my_id[index] is <r_2,f+i>
      //Regarding the last index, C_my_id and D_my_id both contain the necessary value
      rs_my_id_[s] += (C_my_id[index] >> 1) + (D_my_id[index] << i);
      rs_previous_id_[s] += (C_previous_id[index] >> 1) + (D_previous_id[index] << i);
    }
    rs_my_id_[s] -= y.first[s];
    rs_previous_id_[s] -= y.second[s];
  }
  
  rd_done_ = true;
  rd_done_condition_.NotifyAll();
}



}  // namespace encrypto::motion