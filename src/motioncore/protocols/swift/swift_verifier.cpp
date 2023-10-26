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

#include "base/backend.h"
#include "primitives/blake2b.h"
#include "communication/message_manager.h"
#include "communication/message.h"

#include "swift_verifier.h"

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

namespace {
    
uint64_t ConvertIdToIndex(uint64_t other_id, uint64_t my_id) {
  assert(other_id != my_id);
  return (other_id > my_id) ? other_id - 1 : other_id;
}

void Abort() {
  //throw std::runtime_error("Hashes do not match");
  
  //We do not actually abort, since we use garbage values during benchmarking.
  //Instead, we update a volatile counter to prevent the compiler from
  //optimizing out the function and the loop calling it.
  //Comment the lines below and uncomment the line above when running tests.
  static volatile std::atomic<size_t> counter = 0;
  counter.fetch_add(1, std::memory_order_relaxed);
}

}

SwiftHashVerifier::SwiftHashVerifier(Backend& backend)
: backend_{backend}, gate_id_{backend.GetRegister()->NextGateId()},
  dependencies_{2},
  check_is_done_condition_([this](){ return dependencies_.load() == 0; }) {
  using communication::MessageType::kSwiftVerifier;
  auto& communication_layer = backend_.GetCommunicationLayer();
  auto& message_manager = communication_layer.GetMessageManager();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  
  hash_message_futures_[ConvertIdToIndex(next_id, my_id)] = 
    message_manager.RegisterReceive(next_id, kSwiftVerifier, gate_id_);
  hash_message_futures_[ConvertIdToIndex(previous_id, my_id)] = 
    message_manager.RegisterReceive(previous_id, kSwiftVerifier, gate_id_);
}

SwiftHashVerifier::ReservedData ReserveHashImpl(
  std::vector<uint8_t>& input, size_t number_of_hash_bytes) {
  size_t input_size = input.size();
  input.resize(input_size + number_of_hash_bytes);
  return {&input, input_size};
}

SwiftHashVerifier::ReservedData SwiftHashVerifier::ReserveHashMessage(
  size_t number_of_hash_bytes, uint64_t other_id) {
  dependencies_.fetch_add(1);
  auto& communication_layer = backend_.GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t hash_input_id = ConvertIdToIndex(other_id, my_id);
  return ReserveHashImpl(hash_messages_[hash_input_id], number_of_hash_bytes);
}

SwiftHashVerifier::ReservedData SwiftHashVerifier::ReserveHashCheck(
  size_t number_of_hash_bytes, uint64_t other_id) {
  dependencies_.fetch_add(1);
  auto& communication_layer = backend_.GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t hash_input_id = ConvertIdToIndex(other_id, my_id);
  return ReserveHashImpl(hash_checks_[hash_input_id], number_of_hash_bytes);
}

void SwiftHashVerifier::SetReady() {
  size_t dependencies = dependencies_.fetch_sub(1) - 1;
  assert(dependencies != 0);
  //If check_dependencies_ is 1 at this point, all dependencies called SetCheckReady()
  if(dependencies == 1) {
    SendHash();
    CheckHash();
    //We need to set check_dependencies to 0, to notify all dependencies
    dependencies_.store(0);
    check_is_done_condition_.NotifyAll();
  }
}

void SwiftHashVerifier::SendHash() {
  using communication::MessageType::kSwiftVerifier;
  auto& communication_layer = backend_.GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  
  std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
  size_t index = ConvertIdToIndex(next_id, my_id);
  if(hash_messages_[index].size() > 0) {
    Blake2b(
      reinterpret_cast<uint8_t*>(hash_messages_[index].data()), 
      hash.data(), 
      hash_messages_[index].size());
    auto message = communication::BuildMessage(kSwiftVerifier, gate_id_, hash);
    communication_layer.SendMessage(next_id, message.Release());
  }
  index = ConvertIdToIndex(previous_id, my_id);
  if(hash_messages_[index].size() > 0) {
    Blake2b(
      reinterpret_cast<uint8_t*>(hash_messages_[index].data()), 
      hash.data(), 
      hash_messages_[index].size());
    auto message = communication::BuildMessage(kSwiftVerifier, gate_id_, hash);
    communication_layer.SendMessage(previous_id, message.Release());
  }
}
  
void SwiftHashVerifier::CheckHash() {
  auto& communication_layer = backend_.GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  
  std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
  size_t index = ConvertIdToIndex(next_id, my_id);
  if(hash_checks_[index].size() > 0) {
    Blake2b(
      reinterpret_cast<uint8_t*>(hash_checks_[index].data()), 
      hash.data(), 
      hash_checks_[index].size());
    const auto message = hash_message_futures_[index].get();
    const auto payload = communication::GetMessage(message.data())->payload();
    std::vector<uint8_t> received_hash(payload->Data(), payload->Data() + payload->size());
    assert(hash.size() == received_hash.size());
    for(size_t i = 0; i != hash.size(); ++i) {
      if(hash[i] != received_hash[i]) Abort();
    }
  }
  index = ConvertIdToIndex(previous_id, my_id);
  if(hash_checks_[index].size() > 0) {
    Blake2b(
      reinterpret_cast<uint8_t*>(hash_checks_[index].data()), 
      hash.data(), 
      hash_checks_[index].size());
    const auto message = hash_message_futures_[index].get();
    const auto payload = communication::GetMessage(message.data())->payload();
    std::vector<uint8_t> received_hash(payload->Data(), payload->Data() + payload->size());
    assert(hash.size() == received_hash.size());
    for(size_t i = 0; i != hash.size(); ++i) {
      if(hash[i] != received_hash[i]) Abort();
    }
  }
}

SwiftSacrificeVerifier::ReservedTriple64::ReservedTriple64(
SwiftSacrificeVerifier* sacrifice_verify, size_t offset)
: sacrifice_verify_{sacrifice_verify}, offset_{offset} {}

void SwiftSacrificeVerifier::ReservedTriple64::AppendTriple(
  uint64_t lambda_i_x, uint64_t lambda_i_minus_1_x,
  uint64_t lambda_i_y, uint64_t lambda_i_minus_1_y,
  uint64_t gamma_i_xy, uint64_t gamma_i_minus_1_xy) {
  sacrifice_verify_->lambdas_i_x64_[offset_] = std::move(lambda_i_x);
  sacrifice_verify_->lambdas_i_minus_1_x64_[offset_] = std::move(lambda_i_minus_1_x);
  sacrifice_verify_->lambdas_i_y64_[offset_] = std::move(lambda_i_y);
  sacrifice_verify_->lambdas_i_minus_1_y64_[offset_] = std::move(lambda_i_minus_1_y);
  sacrifice_verify_->gammas_i_xy64_[offset_] = std::move(gamma_i_xy);
  sacrifice_verify_->gammas_i_minus_1_xy64_[offset_] = std::move(gamma_i_minus_1_xy);
  ++offset_;
}

SwiftSacrificeVerifier::ReservedTriple128::ReservedTriple128(
SwiftSacrificeVerifier* sacrifice_verify, size_t offset)
: sacrifice_verify_{sacrifice_verify}, offset_{offset} {}

void SwiftSacrificeVerifier::ReservedTriple128::AppendTriple(
  UInt128 lambda_i_x, UInt128 lambda_i_minus_1_x,
  UInt128 lambda_i_y, UInt128 lambda_i_minus_1_y,
  UInt128 gamma_i_xy, UInt128 gamma_i_minus_1_xy) {
  sacrifice_verify_->lambdas_i_x128_[offset_] = std::move(lambda_i_x);
  sacrifice_verify_->lambdas_i_minus_1_x128_[offset_] = std::move(lambda_i_minus_1_x);
  sacrifice_verify_->lambdas_i_y128_[offset_] = std::move(lambda_i_y);
  sacrifice_verify_->lambdas_i_minus_1_y128_[offset_] = std::move(lambda_i_minus_1_y);
  sacrifice_verify_->gammas_i_xy128_[offset_] = std::move(gamma_i_xy);
  sacrifice_verify_->gammas_i_minus_1_xy128_[offset_] = std::move(gamma_i_minus_1_xy);
  ++offset_;
}

SwiftSacrificeVerifier::ReservedMatrixTriple64::ReservedMatrixTriple64(
SwiftSacrificeVerifier* sacrifice_verify, size_t offset)
: sacrifice_verify_{sacrifice_verify}, offset_{offset} {}

void SwiftSacrificeVerifier::ReservedMatrixTriple64::AppendTriple(
  boost::numeric::ublas::matrix<uint64_t> lambda_i_x,
  boost::numeric::ublas::matrix<uint64_t> lambda_i_minus_1_x,
  boost::numeric::ublas::matrix<uint64_t> lambda_i_y, 
  boost::numeric::ublas::matrix<uint64_t> lambda_i_minus_1_y, 
  boost::numeric::ublas::matrix<uint64_t> gamma_i_xy,
  boost::numeric::ublas::matrix<uint64_t> gamma_i_minus_1_xy) {
  sacrifice_verify_->matrix_lambdas_i_x64_[offset_] = 
    std::move(lambda_i_x);
  sacrifice_verify_->matrix_lambdas_i_minus_1_x64_[offset_] = 
    std::move(lambda_i_minus_1_x);
  sacrifice_verify_->matrix_lambdas_i_y64_[offset_] = 
    std::move(lambda_i_y);
  sacrifice_verify_->matrix_lambdas_i_minus_1_y64_[offset_] = 
    std::move(lambda_i_minus_1_y);
  sacrifice_verify_->matrix_gammas_i_xy64_[offset_] = 
    std::move(gamma_i_xy);
  sacrifice_verify_->matrix_gammas_i_minus_1_xy64_[offset_] = 
    std::move(gamma_i_minus_1_xy);
  ++offset_;
}

SwiftSacrificeVerifier::ReservedMatrixTriple128::ReservedMatrixTriple128(
SwiftSacrificeVerifier* sacrifice_verify, size_t offset)
: sacrifice_verify_{sacrifice_verify}, offset_{offset} {}

void SwiftSacrificeVerifier::ReservedMatrixTriple128::AppendTriple(
  boost::numeric::ublas::matrix<UInt128> lambda_i_x,
  boost::numeric::ublas::matrix<UInt128> lambda_i_minus_1_x,
  boost::numeric::ublas::matrix<UInt128> lambda_i_y, 
  boost::numeric::ublas::matrix<UInt128> lambda_i_minus_1_y, 
  boost::numeric::ublas::matrix<UInt128> gamma_i_xy,
  boost::numeric::ublas::matrix<UInt128> gamma_i_minus_1_xy) {
  sacrifice_verify_->matrix_lambdas_i_x128_[offset_] = 
    std::move(lambda_i_x);
  sacrifice_verify_->matrix_lambdas_i_minus_1_x128_[offset_] = 
    std::move(lambda_i_minus_1_x);
  sacrifice_verify_->matrix_lambdas_i_y128_[offset_] = 
    std::move(lambda_i_y);
  sacrifice_verify_->matrix_lambdas_i_minus_1_y128_[offset_] = 
    std::move(lambda_i_minus_1_y);
  sacrifice_verify_->matrix_gammas_i_xy128_[offset_] = 
    std::move(gamma_i_xy);
  sacrifice_verify_->matrix_gammas_i_minus_1_xy128_[offset_] = 
    std::move(gamma_i_minus_1_xy);
  ++offset_;
}

SwiftSacrificeVerifier::ReservedTriple64 
SwiftSacrificeVerifier::ReserveTriples64(size_t number_of_triples) {
  //This method is supposed to be called during circuit definition, thus
  //no synchronization is needed here.
  dependencies_.fetch_add(1);
  size_t old_size = lambdas_i_x64_.size();
  lambdas_i_x64_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_i_minus_1_x64_.size());
  lambdas_i_minus_1_x64_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_i_y64_.size());
  lambdas_i_y64_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_i_minus_1_y64_.size());
  lambdas_i_minus_1_y64_.resize(old_size + number_of_triples);
  assert(old_size == gammas_i_xy64_.size());
  gammas_i_xy64_.resize(old_size + number_of_triples);
  assert(old_size == gammas_i_minus_1_xy64_.size());
  gammas_i_minus_1_xy64_.resize(old_size + number_of_triples);
  return {this, old_size};
}

SwiftSacrificeVerifier::ReservedTriple128 
SwiftSacrificeVerifier::ReserveTriples128(size_t number_of_triples) {
  //This method is supposed to be called during circuit definition, thus
  //no synchronization is needed here.
  dependencies_.fetch_add(1);
  size_t old_size = lambdas_i_x128_.size();
  lambdas_i_x128_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_i_minus_1_x128_.size());
  lambdas_i_minus_1_x128_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_i_y128_.size());
  lambdas_i_y128_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_i_minus_1_y128_.size());
  lambdas_i_minus_1_y128_.resize(old_size + number_of_triples);
  assert(old_size == gammas_i_xy128_.size());
  gammas_i_xy128_.resize(old_size + number_of_triples);
  assert(old_size == gammas_i_minus_1_xy128_.size());
  gammas_i_minus_1_xy128_.resize(old_size + number_of_triples);
  return {this, old_size};
}

SwiftSacrificeVerifier::ReservedMatrixTriple64 
SwiftSacrificeVerifier::ReserveMatrixTriples64(size_t number_of_triples) {
  //This method is supposed to be called during circuit definition, thus
  //no synchronization is needed here.
  dependencies_.fetch_add(1);
  size_t old_size = matrix_lambdas_i_x64_.size();
  matrix_lambdas_i_x64_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_i_minus_1_x64_.size());
  matrix_lambdas_i_minus_1_x64_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_i_y64_.size());
  matrix_lambdas_i_y64_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_i_minus_1_y64_.size());
  matrix_lambdas_i_minus_1_y64_.resize(old_size + number_of_triples);
  assert(old_size == matrix_gammas_i_xy64_.size());
  matrix_gammas_i_xy64_.resize(old_size + number_of_triples);
  assert(old_size == matrix_gammas_i_minus_1_xy64_.size());
  matrix_gammas_i_minus_1_xy64_.resize(old_size + number_of_triples);
  return {this, old_size};
}

SwiftSacrificeVerifier::ReservedMatrixTriple128 
SwiftSacrificeVerifier::ReserveMatrixTriples128(size_t number_of_triples) {
  //This method is supposed to be called during circuit definition, thus
  //no synchronization is needed here.
  dependencies_.fetch_add(1);
  size_t old_size = matrix_lambdas_i_x128_.size();
  matrix_lambdas_i_x128_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_i_minus_1_x128_.size());
  matrix_lambdas_i_minus_1_x128_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_i_y128_.size());
  matrix_lambdas_i_y128_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_i_minus_1_y128_.size());
  matrix_lambdas_i_minus_1_y128_.resize(old_size + number_of_triples);
  assert(old_size == matrix_gammas_i_xy128_.size());
  matrix_gammas_i_xy128_.resize(old_size + number_of_triples);
  assert(old_size == matrix_gammas_i_minus_1_xy128_.size());
  matrix_gammas_i_minus_1_xy128_.resize(old_size + number_of_triples);
  return {this, old_size};
}

SwiftSacrificeVerifier::SwiftSacrificeVerifier(Backend& backend)
: backend_{backend}, gate_id_{backend.GetRegister()->NextGateId()},
  dependencies_{2},
  check_is_done_condition_([this](){ return dependencies_.load() == 0; }) {
  using communication::MessageType::kSwiftVerifierSemiMult;
  using communication::MessageType::kSwiftVerifierR;
  using communication::MessageType::kSwiftVerifierV;
  using communication::MessageType::kSwiftVerifierCheckZero;
  
  auto& communication_layer = backend_.GetCommunicationLayer();
  auto& message_manager = communication_layer.GetMessageManager();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  
  semi_mult_future_ = 
    message_manager.RegisterReceive(previous_id, kSwiftVerifierSemiMult, gate_id_);
  r_future_ = 
    message_manager.RegisterReceive(previous_id, kSwiftVerifierR, gate_id_);
  r_hash_future_ = 
    message_manager.RegisterReceive(next_id, kSwiftVerifierR, gate_id_);
  v_future_ = 
    message_manager.RegisterReceive(previous_id, kSwiftVerifierV, gate_id_);
  v_hash_future_ = 
    message_manager.RegisterReceive(next_id, kSwiftVerifierV, gate_id_);
  previous_id_check_zero_future_ = 
    message_manager.RegisterReceive(previous_id, kSwiftVerifierCheckZero, gate_id_);
  next_id_check_zero_future_ = 
    message_manager.RegisterReceive(next_id, kSwiftVerifierCheckZero, gate_id_);
}

void SwiftSacrificeVerifier::SetReady() {
  size_t dependencies = dependencies_.fetch_sub(1) - 1;
  //If dependencies is 1 at this point, all dependencies called SetReady()
  if(dependencies == 1) {
    Verify();
    //We need to set check_dependencies to 0, to notify all dependencies
    dependencies_.store(0);
    check_is_done_condition_.NotifyAll();
  }
}


void SwiftSacrificeVerifier::Verify() {
  using communication::MessageType::kSwiftVerifierSemiMult;
  using communication::MessageType::kSwiftVerifierR;
  using communication::MessageType::kSwiftVerifierV;
  using communication::MessageType::kSwiftVerifierCheckZero;
  using boost::numeric::ublas::matrix;
  
  auto& communication_layer = backend_.GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  //We assume the role of S_i and use the rng shared with S_i+1
  auto& my_rng = 
    backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
  //We assume the role of S_i+1 and use the rng shared with S_i
  auto& previous_rng = 
    backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
  
  size_t const number_of_triples64 = lambdas_i_x64_.size();
  assert(number_of_triples64 == lambdas_i_y64_.size());
  assert(number_of_triples64 == gammas_i_xy64_.size());
  assert(number_of_triples64 == lambdas_i_minus_1_x64_.size());
  assert(number_of_triples64 == lambdas_i_minus_1_y64_.size());
  assert(number_of_triples64 == gammas_i_minus_1_xy64_.size());
  
  size_t const number_of_triples128 = lambdas_i_x128_.size();
  assert(number_of_triples128 == lambdas_i_y128_.size());
  assert(number_of_triples128 == gammas_i_xy128_.size());
  assert(number_of_triples128 == lambdas_i_minus_1_x128_.size());
  assert(number_of_triples128 == lambdas_i_minus_1_y128_.size());
  assert(number_of_triples128 == gammas_i_minus_1_xy128_.size());
  
  size_t const number_of_matrix_triples64 = matrix_lambdas_i_x64_.size();
  assert(number_of_matrix_triples64 == matrix_lambdas_i_y64_.size());
  assert(number_of_matrix_triples64 == matrix_gammas_i_xy64_.size());
  assert(number_of_matrix_triples64 == matrix_lambdas_i_minus_1_x64_.size());
  assert(number_of_matrix_triples64 == matrix_lambdas_i_minus_1_y64_.size());
  assert(number_of_matrix_triples64 == matrix_gammas_i_minus_1_xy64_.size());
  
  size_t const number_of_matrix_triples128 = matrix_lambdas_i_x128_.size();
  assert(number_of_matrix_triples128 == matrix_lambdas_i_y128_.size());
  assert(number_of_matrix_triples128 == matrix_gammas_i_xy128_.size());
  assert(number_of_matrix_triples128 == matrix_lambdas_i_minus_1_x128_.size());
  assert(number_of_matrix_triples128 == matrix_lambdas_i_minus_1_y128_.size());
  assert(number_of_matrix_triples128 == matrix_gammas_i_minus_1_xy128_.size());
  
  size_t const number_of_triples = 
    number_of_triples64 + number_of_triples128;

  size_t const number_of_matrix_triples = 
    number_of_matrix_triples64 + number_of_matrix_triples128;
    
  //If triples are empty, there's nothing to do. 
  if(number_of_triples + number_of_matrix_triples == 0) {
    return;
  }
  
  size_t const number_of_triples64_bytes = 
    number_of_triples64 * sizeof(uint64_t);
  size_t const number_of_triples128_bytes = 
    number_of_triples128 * sizeof(UInt128);
    
  size_t number_of_matrix_u_w64_bytes = 0;
  size_t number_of_matrix_u_v64_bytes = 0;
  for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
    size_t const u = matrix_lambdas_i_x64_[i].size1();
    size_t const w = matrix_lambdas_i_x64_[i].size2();
    size_t const v = matrix_lambdas_i_y64_[i].size2();
    assert(matrix_lambdas_i_x64_[i].size1() == u);
    assert(matrix_lambdas_i_x64_[i].size2() == w);
    assert(matrix_lambdas_i_minus_1_x64_[i].size1() == u);
    assert(matrix_lambdas_i_minus_1_x64_[i].size2() == w);
    assert(matrix_lambdas_i_y64_[i].size1() == w);
    assert(matrix_lambdas_i_y64_[i].size2() == v);
    assert(matrix_lambdas_i_minus_1_y64_[i].size1() == w);
    assert(matrix_lambdas_i_minus_1_y64_[i].size2() == v);
    assert(matrix_gammas_i_xy64_[i].size1() == u);
    assert(matrix_gammas_i_xy64_[i].size2() == v);
    assert(matrix_gammas_i_minus_1_xy64_[i].size1() == u);
    assert(matrix_gammas_i_minus_1_xy64_[i].size2() == v);
    number_of_matrix_u_w64_bytes += u * w * sizeof(uint64_t);
    number_of_matrix_u_v64_bytes += u * v * sizeof(uint64_t);
  }
  
  size_t number_of_matrix_u_w128_bytes = 0;
  size_t number_of_matrix_u_v128_bytes = 0;
  for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
    size_t const u = matrix_lambdas_i_x128_[i].size1();
    size_t const w = matrix_lambdas_i_x128_[i].size2();
    size_t const v = matrix_lambdas_i_y128_[i].size2();
    assert(matrix_lambdas_i_x128_[i].size1() == u);
    assert(matrix_lambdas_i_x128_[i].size2() == w);
    assert(matrix_lambdas_i_minus_1_x128_[i].size1() == u);
    assert(matrix_lambdas_i_minus_1_x128_[i].size2() == w);
    assert(matrix_lambdas_i_y128_[i].size1() == w);
    assert(matrix_lambdas_i_y128_[i].size2() == v);
    assert(matrix_lambdas_i_minus_1_y128_[i].size1() == w);
    assert(matrix_lambdas_i_minus_1_y128_[i].size2() == v);
    assert(matrix_gammas_i_xy128_[i].size1() == u);
    assert(matrix_gammas_i_xy128_[i].size2() == v);
    assert(matrix_gammas_i_minus_1_xy128_[i].size1() == u);
    assert(matrix_gammas_i_minus_1_xy128_[i].size2() == v);
    number_of_matrix_u_w128_bytes += u * w * sizeof(UInt128);
    number_of_matrix_u_v128_bytes += u * v * sizeof(UInt128);
  }
  
  size_t const number_of_triples_bytes = 
    number_of_triples64_bytes + number_of_triples128_bytes;
  size_t const number_of_matrix_u_w_bytes = 
    number_of_matrix_u_w64_bytes + number_of_matrix_u_w128_bytes;
  size_t const number_of_matrix_u_v_bytes = 
    number_of_matrix_u_v64_bytes + number_of_matrix_u_v128_bytes;
  size_t const number_of_rng_bytes = 
    number_of_triples_bytes + number_of_matrix_u_w_bytes 
    + number_of_triples_bytes + number_of_matrix_u_v_bytes 
    + sizeof(UInt128);
    
  size_t const lambda_x64_prime_offset = 0;
  size_t const lambda_x128_prime_offset = 
    lambda_x64_prime_offset + number_of_triples64_bytes;
  size_t const matrix_lambda_x64_prime_offset =
    lambda_x128_prime_offset + number_of_triples128_bytes;
  size_t const matrix_lambda_x128_prime_offset =
    matrix_lambda_x64_prime_offset + number_of_matrix_u_w64_bytes;
  size_t const alpha64_offset = 
    matrix_lambda_x128_prime_offset + number_of_matrix_u_w128_bytes;
  assert(alpha64_offset == number_of_triples_bytes + number_of_matrix_u_w_bytes);
  size_t const alpha128_offset = 
    alpha64_offset + number_of_triples64_bytes;
  size_t const matrix_alpha64_offset =
    alpha128_offset + number_of_triples128_bytes;
  size_t const matrix_alpha128_offset =
    matrix_alpha64_offset + number_of_matrix_u_v64_bytes;
  size_t const r_offset = 
    matrix_alpha128_offset + number_of_matrix_u_v128_bytes;
  assert(r_offset == 2*number_of_triples_bytes 
                     + number_of_matrix_u_w_bytes 
                     + number_of_matrix_u_v_bytes);
  size_t const gamma_x_prime_y64_offset = alpha64_offset;
  size_t const gamma_x_prime_y128_offset = alpha128_offset;
  size_t const matrix_gamma_x_prime_y64_offset = matrix_alpha64_offset;
  size_t const matrix_gamma_x_prime_y128_offset = matrix_alpha128_offset;
  size_t const v64_offset = lambda_x64_prime_offset;
  size_t const v128_offset = lambda_x128_prime_offset;
  size_t const matrix_v64_offset = matrix_lambda_x64_prime_offset;
  size_t const matrix_v128_offset = matrix_lambda_x128_prime_offset;
  size_t const w64_0_offset = 0;
  size_t const w128_0_offset = number_of_triples64_bytes;
  size_t const matrix_w64_0_offset = 
    w128_0_offset + number_of_triples128_bytes;
  size_t const matrix_w128_0_offset = 
    matrix_w64_0_offset + number_of_matrix_u_v64_bytes;
  size_t const w64_1_offset = 
    matrix_w128_0_offset + number_of_matrix_u_v128_bytes;
  size_t const w128_1_offset = 
    w64_1_offset + number_of_triples64_bytes;
  size_t const matrix_w64_1_offset = 
    w128_1_offset + number_of_triples128_bytes;
  size_t const matrix_w128_1_offset = 
    matrix_w64_1_offset + number_of_matrix_u_v64_bytes;
  size_t const w64_2_offset = 
    matrix_w128_1_offset + number_of_matrix_u_v128_bytes;
  size_t const w128_2_offset = 
    w64_2_offset + number_of_triples64_bytes;
  size_t const matrix_w64_2_offset = 
    w128_2_offset + number_of_triples128_bytes;
  size_t const matrix_w128_2_offset = 
    matrix_w64_2_offset + number_of_matrix_u_v64_bytes;
         
  auto AssignToMatrix = [](auto& mat, uint8_t const* data_pointer) {
    using ArithmeticType = typename std::decay_t<decltype(mat)>::value_type;
    size_t offset = 0;
    for(size_t i = 0; i != mat.size1(); ++i) {
      for(size_t j = 0; j != mat.size2(); ++j) {
        ArithmeticType& v = mat(i, j);
        memcpy(&v, data_pointer + offset, sizeof(ArithmeticType));
        offset += sizeof(ArithmeticType);
      }
    }
  };
  
  auto AssignFromMatrix = [](uint8_t* data_pointer, auto const& mat) {
    using ArithmeticType = typename std::decay_t<decltype(mat)>::value_type;
    size_t offset = 0;
    for(size_t i = 0; i != mat.size1(); ++i) {
      for(size_t j = 0; j != mat.size2(); ++j) {
        ArithmeticType const& v = mat(i, j);
        memcpy(data_pointer + offset, &v, sizeof(ArithmeticType));
        offset += sizeof(ArithmeticType);
      }
    }
  };
  
  //rng_bytes contain lambda_x_prime, alpha and r, respectively
  //For lambda_x_prime and alpha, the order is as follows:
  //64-bit, 128-bit, 64-bit matrix, 128-bit matrix
  std::vector<uint8_t> my_id_rng_bytes = 
    my_rng.template GetUnsigned<uint8_t>(gate_id_, number_of_rng_bytes);
  std::vector<uint8_t> previous_id_rng_bytes = 
    previous_rng.template GetUnsigned<uint8_t>(gate_id_, number_of_rng_bytes);
  
  UInt128 my_id_r;
  memcpy(&my_id_r, my_id_rng_bytes.data() + r_offset, sizeof(UInt128));
  UInt128 previous_id_r;
  memcpy(&previous_id_r, previous_id_rng_bytes.data() + r_offset, sizeof(UInt128));
  
  //Calculate gamma_x_prime_y (step 2)
  {
    uint8_t const* const alpha_i_pointer = 
      my_id_rng_bytes.data() + alpha64_offset;
    uint8_t const* const alpha_i_minus_1_pointer = 
      previous_id_rng_bytes.data() + alpha64_offset;
    uint8_t const* const lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + lambda_x64_prime_offset;
    uint8_t const* const lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + lambda_x64_prime_offset;
    uint8_t* const gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + gamma_x_prime_y64_offset;
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples64; ++i) {
      uint64_t alpha_i, alpha_i_minus_1, 
               lambda_i_x_prime, lambda_i_minus_1_x_prime;
      memcpy(&alpha_i, alpha_i_pointer + offset, sizeof(uint64_t));
      memcpy(&alpha_i_minus_1, 
             alpha_i_minus_1_pointer + offset, 
             sizeof(uint64_t));
      memcpy(&lambda_i_x_prime, 
             lambda_i_x_prime_pointer + offset, 
             sizeof(uint64_t));
      memcpy(&lambda_i_minus_1_x_prime, 
             lambda_i_minus_1_x_prime_pointer + offset, 
             sizeof(uint64_t));
      uint64_t lambda_i_y = lambdas_i_y64_[i],
               lambda_i_minus_1_y = lambdas_i_minus_1_y64_[i];
      uint64_t c_i = lambda_i_x_prime * lambda_i_y
                     + lambda_i_x_prime * lambda_i_minus_1_y
                     + lambda_i_minus_1_x_prime * lambda_i_y
                     + alpha_i - alpha_i_minus_1;
      memcpy(gamma_i_x_prime_y_pointer + offset, &c_i, sizeof(uint64_t));
      offset += sizeof(uint64_t);
    }
  }
  
  {
    uint8_t const* const alpha_i_pointer = 
      my_id_rng_bytes.data() + alpha128_offset;
    uint8_t const* const alpha_i_minus_1_pointer = 
      previous_id_rng_bytes.data() + alpha128_offset;
    uint8_t const* const lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + lambda_x128_prime_offset;
    uint8_t const* const lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + lambda_x128_prime_offset;
    uint8_t* const gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + gamma_x_prime_y128_offset;
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples128; ++i) {
      UInt128 alpha_i, alpha_i_minus_1, 
               lambda_i_x_prime, lambda_i_minus_1_x_prime;
      memcpy(&alpha_i, alpha_i_pointer + offset, sizeof(UInt128));
      memcpy(&alpha_i_minus_1, 
             alpha_i_minus_1_pointer + offset, 
             sizeof(UInt128));
      memcpy(&lambda_i_x_prime, 
             lambda_i_x_prime_pointer + offset, 
             sizeof(UInt128));
      memcpy(&lambda_i_minus_1_x_prime, 
             lambda_i_minus_1_x_prime_pointer + offset, 
             sizeof(UInt128));
      UInt128 lambda_i_y = lambdas_i_y128_[i],
              lambda_i_minus_1_y = lambdas_i_minus_1_y128_[i];
      UInt128 c_i = lambda_i_x_prime * lambda_i_y
                     + lambda_i_x_prime * lambda_i_minus_1_y
                     + lambda_i_minus_1_x_prime * lambda_i_y
                     + alpha_i - alpha_i_minus_1;
      memcpy(gamma_i_x_prime_y_pointer + offset, &c_i, sizeof(UInt128));
      offset += sizeof(UInt128);
    }
  }
  
  {
    uint8_t const* const matrix_alpha_i_pointer = 
      my_id_rng_bytes.data() + matrix_alpha64_offset;
    uint8_t const* const matrix_alpha_i_minus_1_pointer = 
      previous_id_rng_bytes.data() + matrix_alpha64_offset;
    uint8_t const* const matrix_lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + matrix_lambda_x64_prime_offset;
    uint8_t const* const matrix_lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + matrix_lambda_x64_prime_offset;
    uint8_t* const matrix_gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + matrix_gamma_x_prime_y64_offset;
    size_t u_w_offset = 0;
    size_t u_v_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
      size_t const u = matrix_lambdas_i_x64_[i].size1();
      size_t const w = matrix_lambdas_i_x64_[i].size2();
      size_t const v = matrix_lambdas_i_y64_[i].size2();
      matrix<uint64_t> matrix_alpha_i(u, v); 
      matrix<uint64_t> matrix_alpha_i_minus_1(u, v); 
      matrix<uint64_t> matrix_lambda_i_x_prime(u, w);
      matrix<uint64_t> matrix_lambda_i_minus_1_x_prime(u, w);
      
      AssignToMatrix(matrix_alpha_i, 
                     matrix_alpha_i_pointer + u_v_offset);
      AssignToMatrix(matrix_alpha_i_minus_1, 
                     matrix_alpha_i_minus_1_pointer + u_v_offset);
      AssignToMatrix(matrix_lambda_i_x_prime, 
                     matrix_lambda_i_x_prime_pointer + u_w_offset);
      AssignToMatrix(matrix_lambda_i_minus_1_x_prime, 
                     matrix_lambda_i_minus_1_x_prime_pointer + u_w_offset);
      auto& matrix_lambda_i_y = matrix_lambdas_i_y64_[i];
      auto& matrix_lambda_i_minus_1_y = matrix_lambdas_i_minus_1_y64_[i];
      matrix<uint64_t> c_i = 
        prod(matrix_lambda_i_x_prime, matrix_lambda_i_y)
        + prod(matrix_lambda_i_x_prime, matrix_lambda_i_minus_1_y)
        + prod(matrix_lambda_i_minus_1_x_prime, matrix_lambda_i_y)
        + matrix_alpha_i - matrix_alpha_i_minus_1;
      AssignFromMatrix(matrix_gamma_i_x_prime_y_pointer + u_v_offset, c_i);
      u_w_offset += u * w * sizeof(uint64_t);
      u_v_offset += u * v * sizeof(uint64_t);
    }
  }
  
  {
    uint8_t const* const matrix_alpha_i_pointer = 
      my_id_rng_bytes.data() + matrix_alpha128_offset;
    uint8_t const* const matrix_alpha_i_minus_1_pointer = 
      previous_id_rng_bytes.data() + matrix_alpha128_offset;
    uint8_t const* const matrix_lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + matrix_lambda_x128_prime_offset;
    uint8_t const* const matrix_lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + matrix_lambda_x128_prime_offset;
    uint8_t* const matrix_gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + matrix_gamma_x_prime_y128_offset;
    size_t u_w_offset = 0;
    size_t u_v_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
      size_t const u = matrix_lambdas_i_x128_[i].size1();
      size_t const w = matrix_lambdas_i_x128_[i].size2();
      size_t const v = matrix_lambdas_i_y128_[i].size2();
      matrix<UInt128> matrix_alpha_i(u, v); 
      matrix<UInt128> matrix_alpha_i_minus_1(u, v); 
      matrix<UInt128> matrix_lambda_i_x_prime(u, w);
      matrix<UInt128> matrix_lambda_i_minus_1_x_prime(u, w);
      
      AssignToMatrix(matrix_alpha_i, 
                     matrix_alpha_i_pointer + u_v_offset);
      AssignToMatrix(matrix_alpha_i_minus_1, 
                     matrix_alpha_i_minus_1_pointer + u_v_offset);
      AssignToMatrix(matrix_lambda_i_x_prime, 
                     matrix_lambda_i_x_prime_pointer + u_w_offset);
      AssignToMatrix(matrix_lambda_i_minus_1_x_prime, 
                     matrix_lambda_i_minus_1_x_prime_pointer + u_w_offset);
      auto& matrix_lambda_i_y = matrix_lambdas_i_y128_[i];
      auto& matrix_lambda_i_minus_1_y = matrix_lambdas_i_minus_1_y128_[i];
      matrix<UInt128> c_i = 
        prod(matrix_lambda_i_x_prime, matrix_lambda_i_y)
        + prod(matrix_lambda_i_x_prime, matrix_lambda_i_minus_1_y)
        + prod(matrix_lambda_i_minus_1_x_prime, matrix_lambda_i_y)
        + matrix_alpha_i - matrix_alpha_i_minus_1;
      AssignFromMatrix(matrix_gamma_i_x_prime_y_pointer + u_v_offset, c_i);
      u_w_offset += u * w * sizeof(UInt128);
      u_v_offset += u * v * sizeof(UInt128);
    }
  }
  
  //Send my_id_gamma_x_prime_y to next_id 
  {
    auto payload = std::span<uint8_t const>(
      my_id_rng_bytes.data() + gamma_x_prime_y64_offset, number_of_triples_bytes + number_of_matrix_u_v_bytes);
    auto message = 
      communication::BuildMessage(kSwiftVerifierSemiMult, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  //Get previous_id_gamma_x_prime_y
  {
    auto message = semi_mult_future_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    assert(payload->size() == number_of_triples_bytes + number_of_matrix_u_v_bytes);
    memcpy(previous_id_rng_bytes.data() + gamma_x_prime_y64_offset,
           payload->Data(),
           number_of_triples_bytes + number_of_matrix_u_v_bytes);
  }
  
  //Restore r
  {
    //Send r_i-1 to S_i+1
    std::vector<uint8_t> payload;
    payload.reserve(sizeof(previous_id_r));
    for(size_t i = 0; i != sizeof(previous_id_r); ++i) {
      payload.emplace_back(uint8_t((previous_id_r >> (i * CHAR_BIT)) & 0xff));
    }
    auto message = 
      communication::BuildMessage(kSwiftVerifierR, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
  {
    //Send hash of r_i to S_i-1
    Blake2b(
      reinterpret_cast<uint8_t*>(&my_id_r), 
      hash.data(), 
      sizeof(my_id_r));
    auto message = communication::BuildMessage(kSwiftVerifierR, gate_id_, hash);
    communication_layer.SendMessage(previous_id, message.Release());
  }
  UInt128 next_id_r = 0;
  {
    //Receive r_i+1 from S_i-1
    auto message = r_future_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    assert(payload->size() == sizeof(next_id_r));
    std::span<uint8_t const> next_id_r_bytes{payload->Data(), payload->size()};
    for(size_t i = 0; i != sizeof(next_id_r); ++i) {
      next_id_r |= UInt128(next_id_r_bytes[i]) << (i * CHAR_BIT);
    }
    Blake2b(
      reinterpret_cast<uint8_t*>(&next_id_r), 
      hash.data(), 
      sizeof(next_id_r));
    //Receive H(r_i+1) from S_i+1
    auto message_hash = r_hash_future_.get();
    auto payload_hash = 
      communication::GetMessage(message_hash.data())->payload();
    std::vector<uint8_t> received_hash(
      payload_hash->Data(), payload_hash->Data() + payload_hash->size());
    assert(hash.size() == received_hash.size());
    //Compare hash with received hash and abort if they are not equal
    for(size_t i = 0; i != hash.size(); ++i) {
      if(hash[i] != received_hash[i]) Abort();
    }
  }
  UInt128 r128 = previous_id_r + my_id_r + next_id_r;
  uint64_t r64 = uint64_t(r128);
  
  //Calculate v
  {
    uint8_t* lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + lambda_x64_prime_offset;
    uint8_t* lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + lambda_x64_prime_offset;
    //We overwrite the lambda_x' values with v
    uint8_t* v_i_pointer = lambda_i_x_prime_pointer;
    uint8_t* v_i_minus_1_pointer = lambda_i_minus_1_x_prime_pointer;
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples64; ++i) {
      uint64_t lambda_i_x_prime, lambda_i_minus_1_x_prime;
      memcpy(&lambda_i_x_prime, 
             lambda_i_x_prime_pointer + offset, 
             sizeof(uint64_t));
      memcpy(&lambda_i_minus_1_x_prime, 
             lambda_i_minus_1_x_prime_pointer + offset, 
             sizeof(uint64_t));
      uint64_t lambda_i_x = lambdas_i_x64_[i];
      uint64_t lambda_i_minus_1_x = lambdas_i_minus_1_x64_[i];
      uint64_t v_i = r64 * lambda_i_x - lambda_i_x_prime;
      memcpy(v_i_pointer + offset, &v_i, sizeof(uint64_t));
      uint64_t v_i_minus_1 = 
        r64 * lambda_i_minus_1_x - lambda_i_minus_1_x_prime;
      memcpy(v_i_minus_1_pointer + offset, &v_i_minus_1, sizeof(uint64_t));
      offset += sizeof(uint64_t);
    }
  }
  
  {
    uint8_t* lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + lambda_x128_prime_offset;
    uint8_t* lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + lambda_x128_prime_offset;
    //We overwrite the lambda_x' values with v
    uint8_t* v_i_pointer = lambda_i_x_prime_pointer;
    uint8_t* v_i_minus_1_pointer = lambda_i_minus_1_x_prime_pointer;
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples128; ++i) {
      UInt128 lambda_i_x_prime, lambda_i_minus_1_x_prime;
      memcpy(&lambda_i_x_prime, 
             lambda_i_x_prime_pointer + offset, 
             sizeof(UInt128));
      memcpy(&lambda_i_minus_1_x_prime, 
             lambda_i_minus_1_x_prime_pointer + offset, 
             sizeof(UInt128));
      UInt128 lambda_i_x = lambdas_i_x128_[i];
      UInt128 lambda_i_minus_1_x = lambdas_i_minus_1_x128_[i];
      UInt128 v_i = r128 * lambda_i_x - lambda_i_x_prime;
      memcpy(v_i_pointer + offset, &v_i, sizeof(UInt128));
      UInt128 v_i_minus_1 = 
        r128 * lambda_i_minus_1_x - lambda_i_minus_1_x_prime;
      memcpy(v_i_minus_1_pointer + offset, &v_i_minus_1, sizeof(UInt128));
      offset += sizeof(UInt128);
    }
  }
  
  {
    uint8_t* matrix_lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + matrix_lambda_x64_prime_offset;
    uint8_t* matrix_lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + matrix_lambda_x64_prime_offset;
    //We overwrite the lambda_x' values with v
    uint8_t* v_i_pointer = matrix_lambda_i_x_prime_pointer;
    uint8_t* v_i_minus_1_pointer = matrix_lambda_i_minus_1_x_prime_pointer;
    size_t u_w_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
      size_t const u = matrix_lambdas_i_x64_[i].size1();
      size_t const w = matrix_lambdas_i_x64_[i].size2();
      matrix<uint64_t> matrix_lambda_i_x_prime(u, w); 
      matrix<uint64_t> matrix_lambda_i_minus_1_x_prime(u, w);
      AssignToMatrix(matrix_lambda_i_x_prime, 
                     matrix_lambda_i_x_prime_pointer + u_w_offset);
      AssignToMatrix(matrix_lambda_i_minus_1_x_prime, 
                     matrix_lambda_i_minus_1_x_prime_pointer + u_w_offset);
      auto& matrix_lambda_i_x = matrix_lambdas_i_x64_[i];
      auto& matrix_lambda_i_minus_1_x = matrix_lambdas_i_minus_1_x64_[i];
      matrix<uint64_t> matrix_v = 
        r64 * matrix_lambda_i_x - matrix_lambda_i_x_prime;
      AssignFromMatrix(v_i_pointer + u_w_offset, matrix_v);
      matrix_v = 
        r64 * matrix_lambda_i_minus_1_x - matrix_lambda_i_minus_1_x_prime;
      AssignFromMatrix(v_i_minus_1_pointer + u_w_offset, matrix_v);
      u_w_offset += u * w * sizeof(uint64_t);
    }
  }
  
  {
    uint8_t* matrix_lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + matrix_lambda_x128_prime_offset;
    uint8_t* matrix_lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + matrix_lambda_x128_prime_offset;
    //We overwrite the lambda_x' values with v
    uint8_t* v_i_pointer = matrix_lambda_i_x_prime_pointer;
    uint8_t* v_i_minus_1_pointer = matrix_lambda_i_minus_1_x_prime_pointer;
    size_t u_w_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
      size_t const u = matrix_lambdas_i_x128_[i].size1();
      size_t const w = matrix_lambdas_i_x128_[i].size2();
      matrix<UInt128> matrix_lambda_i_x_prime(u, w); 
      matrix<UInt128> matrix_lambda_i_minus_1_x_prime(u, w);
      AssignToMatrix(matrix_lambda_i_x_prime, 
                     matrix_lambda_i_x_prime_pointer + u_w_offset);
      AssignToMatrix(matrix_lambda_i_minus_1_x_prime, 
                     matrix_lambda_i_minus_1_x_prime_pointer + u_w_offset);
      auto& matrix_lambda_i_x = matrix_lambdas_i_x128_[i];
      auto& matrix_lambda_i_minus_1_x = matrix_lambdas_i_minus_1_x128_[i];
      matrix<UInt128> matrix_v = 
        r128 * matrix_lambda_i_x - matrix_lambda_i_x_prime;
      AssignFromMatrix(v_i_pointer + u_w_offset, matrix_v);
      matrix_v = 
        r128 * matrix_lambda_i_minus_1_x - matrix_lambda_i_minus_1_x_prime;
      AssignFromMatrix(v_i_minus_1_pointer + u_w_offset, matrix_v);
      u_w_offset += u * w * sizeof(UInt128);
    }
  }
  //v is now where lambda_x' was
  
  //Restore v
  {
    //Send v_i-1 to S_i+1
    std::span<uint8_t const> payload(
      previous_id_rng_bytes.data() + v64_offset, 
      number_of_triples_bytes + number_of_matrix_u_w_bytes);
    auto message = 
      communication::BuildMessage(kSwiftVerifierV, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  
  {
    //Send hash of v_i to S_i-1
    Blake2b(
      my_id_rng_bytes.data() + v64_offset, 
      hash.data(), 
      number_of_triples_bytes + number_of_matrix_u_w_bytes);
    auto message = communication::BuildMessage(kSwiftVerifierV, gate_id_, hash);
    communication_layer.SendMessage(previous_id, message.Release());
  }
  std::vector<uint8_t> next_id_v_bytes;
  next_id_v_bytes.reserve(number_of_triples_bytes + number_of_matrix_u_w_bytes);
  {
    //Receive v_i+1 from S_i-1
    auto message = v_future_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    assert(payload->size() == number_of_triples_bytes + number_of_matrix_u_w_bytes);
    next_id_v_bytes.insert(
      next_id_v_bytes.end(), payload->Data(), payload->Data() + payload->size());
    //calculate hash of next_id_v
    Blake2b(
      next_id_v_bytes.data(), 
      hash.data(), 
      next_id_v_bytes.size());
    //Receive H(v_i+1) from S_i+1
    auto message_hash = v_hash_future_.get();
    auto payload_hash = 
      communication::GetMessage(message_hash.data())->payload();
    std::vector<uint8_t> received_hash(
      payload_hash->Data(), payload_hash->Data() + payload_hash->size());
    assert(hash.size() == received_hash.size());
    //Compare hash with received hash and abort if they are not equal
    for(size_t i = 0; i != hash.size(); ++i) {
      if(hash[i] != received_hash[i]) Abort();
    }
  }
  
  //Calculate w
  std::vector<uint8_t> w_bytes(3 * (number_of_triples_bytes + number_of_matrix_u_v_bytes));
  {
    uint8_t* v_i_pointer = my_id_rng_bytes.data() + v64_offset;
    uint8_t* v_i_minus_1_pointer = previous_id_rng_bytes.data() + v64_offset;
    uint8_t* v_i_plus_1_pointer = next_id_v_bytes.data() + v64_offset;
    uint8_t* gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + gamma_x_prime_y64_offset;
    uint8_t* gamma_i_minus_1_x_prime_y_pointer = 
      previous_id_rng_bytes.data() + gamma_x_prime_y64_offset;
    std::array<uint8_t*, 3> w_pointers{
      w_bytes.data() + w64_0_offset,
      w_bytes.data() + w64_1_offset,
      w_bytes.data() + w64_2_offset
    };
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples64; ++i) {
      uint64_t v_i, v_i_minus_1, v_i_plus_1,
               gamma_i_x_prime_y, gamma_i_minus_1_x_prime_y;
      memcpy(&v_i, v_i_pointer + offset, sizeof(uint64_t));
      memcpy(&v_i_minus_1, v_i_minus_1_pointer + offset, sizeof(uint64_t));
      memcpy(&v_i_plus_1, v_i_plus_1_pointer + offset, sizeof(uint64_t));
      memcpy(&gamma_i_x_prime_y, 
             gamma_i_x_prime_y_pointer + offset, 
             sizeof(uint64_t));
      memcpy(&gamma_i_minus_1_x_prime_y, 
             gamma_i_minus_1_x_prime_y_pointer + offset, 
             sizeof(uint64_t));
      uint64_t lambda_i_y = lambdas_i_y64_[i];
      uint64_t lambda_i_minus_1_y = lambdas_i_minus_1_y64_[i];
      uint64_t gamma_i_xy = gammas_i_xy64_[i];
      uint64_t gamma_i_minus_1_xy = gammas_i_minus_1_xy64_[i];
      uint64_t v = v_i_minus_1 + v_i + v_i_plus_1;
      uint64_t w_i = v * lambda_i_y - r64 * gamma_i_xy + gamma_i_x_prime_y;
      uint64_t w_i_minus_1 = 
        v * lambda_i_minus_1_y 
        - r64 * gamma_i_minus_1_xy 
        + gamma_i_minus_1_x_prime_y;
      uint64_t w_i_plus_1 = -w_i - w_i_minus_1;
      memcpy(w_pointers[my_id] + offset, &w_i, sizeof(uint64_t));
      memcpy(w_pointers[previous_id] + offset, &w_i_minus_1, sizeof(uint64_t));
      memcpy(w_pointers[next_id] + offset, &w_i_plus_1, sizeof(uint64_t));
      offset += sizeof(uint64_t);
    }
  }
  
  {
    uint8_t* v_i_pointer = my_id_rng_bytes.data() + v128_offset;
    uint8_t* v_i_minus_1_pointer = previous_id_rng_bytes.data() + v128_offset;
    uint8_t* v_i_plus_1_pointer = next_id_v_bytes.data() + v128_offset;
    uint8_t* gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + gamma_x_prime_y128_offset;
    uint8_t* gamma_i_minus_1_x_prime_y_pointer = 
      previous_id_rng_bytes.data() + gamma_x_prime_y128_offset;
    std::array<uint8_t*, 3> w_pointers{
      w_bytes.data() + w128_0_offset,
      w_bytes.data() + w128_1_offset,
      w_bytes.data() + w128_2_offset
    };
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples128; ++i) {
      UInt128 v_i, v_i_minus_1, v_i_plus_1,
               gamma_i_x_prime_y, gamma_i_minus_1_x_prime_y;
      memcpy(&v_i, v_i_pointer + offset, sizeof(UInt128));
      memcpy(&v_i_minus_1, v_i_minus_1_pointer + offset, sizeof(UInt128));
      memcpy(&v_i_plus_1, v_i_plus_1_pointer + offset, sizeof(UInt128));
      memcpy(&gamma_i_x_prime_y, 
             gamma_i_x_prime_y_pointer + offset, 
             sizeof(UInt128));
      memcpy(&gamma_i_minus_1_x_prime_y, 
             gamma_i_minus_1_x_prime_y_pointer + offset, 
             sizeof(UInt128));
      UInt128 lambda_i_y = lambdas_i_y128_[i];
      UInt128 lambda_i_minus_1_y = lambdas_i_minus_1_y128_[i];
      UInt128 gamma_i_xy = gammas_i_xy128_[i];
      UInt128 gamma_i_minus_1_xy = gammas_i_minus_1_xy128_[i];
      UInt128 v = v_i_minus_1 + v_i + v_i_plus_1;
      UInt128 w_i = v * lambda_i_y - r128 * gamma_i_xy + gamma_i_x_prime_y;
      UInt128 w_i_minus_1 = 
        v * lambda_i_minus_1_y 
        - r128 * gamma_i_minus_1_xy 
        + gamma_i_minus_1_x_prime_y;
      UInt128 w_i_plus_1 = -(w_i + w_i_minus_1);
      memcpy(w_pointers[my_id] + offset, &w_i, sizeof(UInt128));
      memcpy(w_pointers[previous_id] + offset, &w_i_minus_1, sizeof(UInt128));
      memcpy(w_pointers[next_id] + offset, &w_i_plus_1, sizeof(UInt128));
      offset += sizeof(UInt128);
    }
  }
  
  {
    uint8_t* matrix_v_i_pointer = 
      my_id_rng_bytes.data() + matrix_v64_offset;
    uint8_t* matrix_v_i_minus_1_pointer = 
      previous_id_rng_bytes.data() + matrix_v64_offset;
    uint8_t* matrix_v_i_plus_1_pointer = 
      next_id_v_bytes.data() + matrix_v64_offset;
    uint8_t* matrix_gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + matrix_gamma_x_prime_y64_offset;
    uint8_t* matrix_gamma_i_minus_1_x_prime_y_pointer = 
      previous_id_rng_bytes.data() + matrix_gamma_x_prime_y64_offset;
    std::array<uint8_t*, 3> matrix_w_pointers{
      w_bytes.data() + matrix_w64_0_offset,
      w_bytes.data() + matrix_w64_1_offset,
      w_bytes.data() + matrix_w64_2_offset
    };
    size_t u_w_offset = 0;
    size_t u_v_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
      size_t const u = matrix_lambdas_i_x64_[i].size1();
      size_t const w = matrix_lambdas_i_x64_[i].size2();
      size_t const v = matrix_lambdas_i_y64_[i].size2();
      matrix<uint64_t> matrix_v(u, w);
      matrix<uint64_t> matrix_gamma_i_x_prime_y(u, v);
      matrix<uint64_t> matrix_gamma_i_minus_1_x_prime_y(u, v);
      
      AssignToMatrix(matrix_v, matrix_v_i_pointer + u_w_offset);
      {
        matrix<uint64_t> matrix_v_tmp(u, w);
        AssignToMatrix(matrix_v_tmp, matrix_v_i_minus_1_pointer + u_w_offset);
        matrix_v += matrix_v_tmp;
        AssignToMatrix(matrix_v_tmp, matrix_v_i_plus_1_pointer + u_w_offset);
        matrix_v += matrix_v_tmp;
      }
      
      AssignToMatrix(matrix_gamma_i_x_prime_y, 
                     matrix_gamma_i_x_prime_y_pointer + u_v_offset);
      AssignToMatrix(matrix_gamma_i_minus_1_x_prime_y, 
                     matrix_gamma_i_minus_1_x_prime_y_pointer + u_v_offset);
                     
      auto& matrix_lambda_i_y = matrix_lambdas_i_y64_[i];
      auto& matrix_lambda_i_minus_1_y = matrix_lambdas_i_minus_1_y64_[i];
      auto& matrix_gamma_i_xy = matrix_gammas_i_xy64_[i];
      auto& matrix_gamma_i_minus_1_xy = matrix_gammas_i_minus_1_xy64_[i];
      matrix<uint64_t> matrix_w_i = 
        prod(matrix_v, matrix_lambda_i_y) 
        - r64 * matrix_gamma_i_xy 
        + matrix_gamma_i_x_prime_y;
      matrix<uint64_t> matrix_w_i_minus_1 = 
        prod(matrix_v, matrix_lambda_i_minus_1_y)
        - r64 * matrix_gamma_i_minus_1_xy 
        + matrix_gamma_i_minus_1_x_prime_y;
      matrix<uint64_t> matrix_w_i_plus_1 = 
        -matrix_w_i - matrix_w_i_minus_1;
      AssignFromMatrix(matrix_w_pointers[my_id] + u_v_offset, matrix_w_i);
      AssignFromMatrix(matrix_w_pointers[previous_id] + u_v_offset, matrix_w_i_minus_1);
      AssignFromMatrix(matrix_w_pointers[next_id] + u_v_offset, matrix_w_i_plus_1);
      u_w_offset += u * w * sizeof(uint64_t);
      u_v_offset += u * v * sizeof(uint64_t);
    }
  }
  
  {
    uint8_t* matrix_v_i_pointer = 
      my_id_rng_bytes.data() + matrix_v128_offset;
    uint8_t* matrix_v_i_minus_1_pointer = 
      previous_id_rng_bytes.data() + matrix_v128_offset;
    uint8_t* matrix_v_i_plus_1_pointer = 
      next_id_v_bytes.data() + matrix_v128_offset;
    uint8_t* matrix_gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + matrix_gamma_x_prime_y128_offset;
    uint8_t* matrix_gamma_i_minus_1_x_prime_y_pointer = 
      previous_id_rng_bytes.data() + matrix_gamma_x_prime_y128_offset;
    std::array<uint8_t*, 3> matrix_w_pointers{
      w_bytes.data() + matrix_w128_0_offset,
      w_bytes.data() + matrix_w128_1_offset,
      w_bytes.data() + matrix_w128_2_offset
    };
    size_t u_w_offset = 0;
    size_t u_v_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
      size_t const u = matrix_lambdas_i_x128_[i].size1();
      size_t const w = matrix_lambdas_i_x128_[i].size2();
      size_t const v = matrix_lambdas_i_y128_[i].size2();
      matrix<UInt128> matrix_v(u, w);
      matrix<UInt128> matrix_gamma_i_x_prime_y(u, v);
      matrix<UInt128> matrix_gamma_i_minus_1_x_prime_y(u, v);
      
      AssignToMatrix(matrix_v, matrix_v_i_pointer + u_w_offset);
      {
        matrix<UInt128> matrix_v_tmp(u, w);
        AssignToMatrix(matrix_v_tmp, matrix_v_i_minus_1_pointer + u_w_offset);
        matrix_v += matrix_v_tmp;
        AssignToMatrix(matrix_v_tmp, matrix_v_i_plus_1_pointer + u_w_offset);
        matrix_v += matrix_v_tmp;
      }
      
      AssignToMatrix(matrix_gamma_i_x_prime_y, 
                     matrix_gamma_i_x_prime_y_pointer + u_v_offset);
      AssignToMatrix(matrix_gamma_i_minus_1_x_prime_y, 
                     matrix_gamma_i_minus_1_x_prime_y_pointer + u_v_offset);
                     
      auto& matrix_lambda_i_y = matrix_lambdas_i_y128_[i];
      auto& matrix_lambda_i_minus_1_y = matrix_lambdas_i_minus_1_y128_[i];
      auto& matrix_gamma_i_xy = matrix_gammas_i_xy128_[i];
      auto& matrix_gamma_i_minus_1_xy = matrix_gammas_i_minus_1_xy128_[i];
      matrix<UInt128> matrix_w_i = 
        prod(matrix_v, matrix_lambda_i_y) 
        - r128 * matrix_gamma_i_xy
        + matrix_gamma_i_x_prime_y;
      matrix<UInt128> matrix_w_i_minus_1 = 
        prod(matrix_v, matrix_lambda_i_minus_1_y)
        - r128 * matrix_gamma_i_minus_1_xy
        + matrix_gamma_i_minus_1_x_prime_y;
      matrix<UInt128> matrix_w_i_plus_1 = 
        -matrix_w_i - matrix_w_i_minus_1;
      AssignFromMatrix(matrix_w_pointers[my_id] + u_v_offset, matrix_w_i);
      AssignFromMatrix(matrix_w_pointers[previous_id] + u_v_offset, matrix_w_i_minus_1);
      AssignFromMatrix(matrix_w_pointers[next_id] + u_v_offset, matrix_w_i_plus_1);
      u_w_offset += u * w * sizeof(UInt128);
      u_v_offset += u * v * sizeof(UInt128);
    }
  }
  
  //Now we run CheckZero
  Blake2b(w_bytes.data(), hash.data(), w_bytes.size());
  {
    auto message = communication::BuildMessage(kSwiftVerifierCheckZero, gate_id_, hash);
    communication_layer.BroadcastMessage(message.Release());
  }
  
  {  
    auto message = previous_id_check_zero_future_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    std::vector<uint8_t> previous_id_received_hash(
      payload->Data(), payload->Data() + payload->size());
    assert(hash.size() == previous_id_received_hash.size());
    auto message_hash = next_id_check_zero_future_.get();
    auto payload_hash = 
      communication::GetMessage(message_hash.data())->payload();
    std::vector<uint8_t> next_id_received_hash(
      payload_hash->Data(), payload_hash->Data() + payload_hash->size());
    assert(hash.size() == next_id_received_hash.size());
    //Compare hash with received hashes and abort if they are not equal
    for(size_t i = 0; i != hash.size(); ++i) {
      if(hash[i] != previous_id_received_hash[i] 
         || hash[i] != next_id_received_hash[i]) {
        Abort();
      }
    }
  }
}

SociumSacrificeVerifier::ReservedTriple64::ReservedTriple64(
SociumSacrificeVerifier* sacrifice_verify, size_t offset)
: sacrifice_verify_{sacrifice_verify}, offset_{offset} {}

void SociumSacrificeVerifier::ReservedTriple64::AppendTriple(
  uint64_t lambda_i_x, uint64_t lambda_i_minus_1_x,
  uint64_t lambda_i_y, uint64_t lambda_i_minus_1_y,
  uint64_t gamma_i_xy, uint64_t gamma_i_minus_1_xy) {
  sacrifice_verify_->lambdas_i_x64_[offset_] = std::move(lambda_i_x);
  sacrifice_verify_->lambdas_i_minus_1_x64_[offset_] = std::move(lambda_i_minus_1_x);
  sacrifice_verify_->lambdas_i_y64_[offset_] = std::move(lambda_i_y);
  sacrifice_verify_->lambdas_i_minus_1_y64_[offset_] = std::move(lambda_i_minus_1_y);
  sacrifice_verify_->gammas_i_xy64_[offset_] = std::move(gamma_i_xy);
  sacrifice_verify_->gammas_i_minus_1_xy64_[offset_] = std::move(gamma_i_minus_1_xy);
  ++offset_;
}

SociumSacrificeVerifier::ReservedTriple128::ReservedTriple128(
SociumSacrificeVerifier* sacrifice_verify, size_t offset)
: sacrifice_verify_{sacrifice_verify}, offset_{offset} {}

void SociumSacrificeVerifier::ReservedTriple128::AppendTriple(
  UInt128 lambda_i_x, UInt128 lambda_i_minus_1_x,
  UInt128 lambda_i_y, UInt128 lambda_i_minus_1_y,
  UInt128 gamma_i_xy, UInt128 gamma_i_minus_1_xy) {
  sacrifice_verify_->lambdas_i_x128_[offset_] = std::move(lambda_i_x);
  sacrifice_verify_->lambdas_i_minus_1_x128_[offset_] = std::move(lambda_i_minus_1_x);
  sacrifice_verify_->lambdas_i_y128_[offset_] = std::move(lambda_i_y);
  sacrifice_verify_->lambdas_i_minus_1_y128_[offset_] = std::move(lambda_i_minus_1_y);
  sacrifice_verify_->gammas_i_xy128_[offset_] = std::move(gamma_i_xy);
  sacrifice_verify_->gammas_i_minus_1_xy128_[offset_] = std::move(gamma_i_minus_1_xy);
  ++offset_;
}

SociumSacrificeVerifier::ReservedMatrixTriple64::ReservedMatrixTriple64(
SociumSacrificeVerifier* sacrifice_verify, size_t offset)
: sacrifice_verify_{sacrifice_verify}, offset_{offset} {}

void SociumSacrificeVerifier::ReservedMatrixTriple64::AppendTriple(
  boost::numeric::ublas::matrix<uint64_t> lambda_i_x,
  boost::numeric::ublas::matrix<uint64_t> lambda_i_minus_1_x,
  boost::numeric::ublas::matrix<uint64_t> lambda_i_y, 
  boost::numeric::ublas::matrix<uint64_t> lambda_i_minus_1_y, 
  boost::numeric::ublas::matrix<uint64_t> gamma_i_xy,
  boost::numeric::ublas::matrix<uint64_t> gamma_i_minus_1_xy) {
  sacrifice_verify_->matrix_lambdas_i_x64_[offset_] = 
    std::move(lambda_i_x);
  sacrifice_verify_->matrix_lambdas_i_minus_1_x64_[offset_] = 
    std::move(lambda_i_minus_1_x);
  sacrifice_verify_->matrix_lambdas_i_y64_[offset_] = 
    std::move(lambda_i_y);
  sacrifice_verify_->matrix_lambdas_i_minus_1_y64_[offset_] = 
    std::move(lambda_i_minus_1_y);
  sacrifice_verify_->matrix_gammas_i_xy64_[offset_] = 
    std::move(gamma_i_xy);
  sacrifice_verify_->matrix_gammas_i_minus_1_xy64_[offset_] = 
    std::move(gamma_i_minus_1_xy);
  ++offset_;
}

SociumSacrificeVerifier::ReservedMatrixTriple128::ReservedMatrixTriple128(
SociumSacrificeVerifier* sacrifice_verify, size_t offset)
: sacrifice_verify_{sacrifice_verify}, offset_{offset} {}

void SociumSacrificeVerifier::ReservedMatrixTriple128::AppendTriple(
  boost::numeric::ublas::matrix<UInt128> lambda_i_x,
  boost::numeric::ublas::matrix<UInt128> lambda_i_minus_1_x,
  boost::numeric::ublas::matrix<UInt128> lambda_i_y, 
  boost::numeric::ublas::matrix<UInt128> lambda_i_minus_1_y, 
  boost::numeric::ublas::matrix<UInt128> gamma_i_xy,
  boost::numeric::ublas::matrix<UInt128> gamma_i_minus_1_xy) {
  sacrifice_verify_->matrix_lambdas_i_x128_[offset_] = 
    std::move(lambda_i_x);
  sacrifice_verify_->matrix_lambdas_i_minus_1_x128_[offset_] = 
    std::move(lambda_i_minus_1_x);
  sacrifice_verify_->matrix_lambdas_i_y128_[offset_] = 
    std::move(lambda_i_y);
  sacrifice_verify_->matrix_lambdas_i_minus_1_y128_[offset_] = 
    std::move(lambda_i_minus_1_y);
  sacrifice_verify_->matrix_gammas_i_xy128_[offset_] = 
    std::move(gamma_i_xy);
  sacrifice_verify_->matrix_gammas_i_minus_1_xy128_[offset_] = 
    std::move(gamma_i_minus_1_xy);
  ++offset_;
}

SociumSacrificeVerifier::ReservedTriple64 
SociumSacrificeVerifier::ReserveTriples64(size_t number_of_triples) {
  //This method is supposed to be called during circuit definition, thus
  //no synchronization is needed here.
  dependencies_.fetch_add(1);
  size_t old_size = lambdas_i_x64_.size();
  lambdas_i_x64_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_i_minus_1_x64_.size());
  lambdas_i_minus_1_x64_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_i_y64_.size());
  lambdas_i_y64_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_i_minus_1_y64_.size());
  lambdas_i_minus_1_y64_.resize(old_size + number_of_triples);
  assert(old_size == gammas_i_xy64_.size());
  gammas_i_xy64_.resize(old_size + number_of_triples);
  assert(old_size == gammas_i_minus_1_xy64_.size());
  gammas_i_minus_1_xy64_.resize(old_size + number_of_triples);
  return {this, old_size};
}

SociumSacrificeVerifier::ReservedTriple128 
SociumSacrificeVerifier::ReserveTriples128(size_t number_of_triples) {
  //This method is supposed to be called during circuit definition, thus
  //no synchronization is needed here.
  dependencies_.fetch_add(1);
  size_t old_size = lambdas_i_x128_.size();
  lambdas_i_x128_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_i_minus_1_x128_.size());
  lambdas_i_minus_1_x128_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_i_y128_.size());
  lambdas_i_y128_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_i_minus_1_y128_.size());
  lambdas_i_minus_1_y128_.resize(old_size + number_of_triples);
  assert(old_size == gammas_i_xy128_.size());
  gammas_i_xy128_.resize(old_size + number_of_triples);
  assert(old_size == gammas_i_minus_1_xy128_.size());
  gammas_i_minus_1_xy128_.resize(old_size + number_of_triples);
  return {this, old_size};
}

SociumSacrificeVerifier::ReservedMatrixTriple64 
SociumSacrificeVerifier::ReserveMatrixTriples64(size_t number_of_triples) {
  //This method is supposed to be called during circuit definition, thus
  //no synchronization is needed here.
  dependencies_.fetch_add(1);
  size_t old_size = matrix_lambdas_i_x64_.size();
  matrix_lambdas_i_x64_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_i_minus_1_x64_.size());
  matrix_lambdas_i_minus_1_x64_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_i_y64_.size());
  matrix_lambdas_i_y64_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_i_minus_1_y64_.size());
  matrix_lambdas_i_minus_1_y64_.resize(old_size + number_of_triples);
  assert(old_size == matrix_gammas_i_xy64_.size());
  matrix_gammas_i_xy64_.resize(old_size + number_of_triples);
  assert(old_size == matrix_gammas_i_minus_1_xy64_.size());
  matrix_gammas_i_minus_1_xy64_.resize(old_size + number_of_triples);
  return {this, old_size};
}

SociumSacrificeVerifier::ReservedMatrixTriple128 
SociumSacrificeVerifier::ReserveMatrixTriples128(size_t number_of_triples) {
  //This method is supposed to be called during circuit definition, thus
  //no synchronization is needed here.
  dependencies_.fetch_add(1);
  size_t old_size = matrix_lambdas_i_x128_.size();
  matrix_lambdas_i_x128_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_i_minus_1_x128_.size());
  matrix_lambdas_i_minus_1_x128_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_i_y128_.size());
  matrix_lambdas_i_y128_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_i_minus_1_y128_.size());
  matrix_lambdas_i_minus_1_y128_.resize(old_size + number_of_triples);
  assert(old_size == matrix_gammas_i_xy128_.size());
  matrix_gammas_i_xy128_.resize(old_size + number_of_triples);
  assert(old_size == matrix_gammas_i_minus_1_xy128_.size());
  matrix_gammas_i_minus_1_xy128_.resize(old_size + number_of_triples);
  return {this, old_size};
}

SociumSacrificeVerifier::SociumSacrificeVerifier(Backend& backend)
: backend_{backend}, gate_id_{backend.GetRegister()->NextGateId()},
  dependencies_{2},
  check_is_done_condition_([this](){ return dependencies_.load() == 0; }) {
  using communication::MessageType::kSociumVerifierSemiMult;
  using communication::MessageType::kSociumVerifierV;
  using communication::MessageType::kSociumVerifierCheckZero;
  
  auto& communication_layer = backend_.GetCommunicationLayer();
  auto& message_manager = communication_layer.GetMessageManager();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;

  if (my_id == 0) {
    semi_mult_future_ = 
      message_manager.RegisterReceive(previous_id, kSociumVerifierSemiMult, gate_id_);
    v_future_ = 
      message_manager.RegisterReceive(next_id, kSociumVerifierV, gate_id_);
  } else if (my_id == 1) {
    v_future_ = 
      message_manager.RegisterReceive(previous_id, kSociumVerifierV, gate_id_);
    check_zero_future_ = 
      message_manager.RegisterReceive(previous_id, kSociumVerifierCheckZero, gate_id_);
  }
}

void SociumSacrificeVerifier::SetReady() {
  size_t dependencies = dependencies_.fetch_sub(1) - 1;
  //If dependencies is 1 at this point, all dependencies called SetReady()
  if(dependencies == 1) {
    Verify();
    //We need to set check_dependencies to 0, to notify all dependencies
    dependencies_.store(0);
    check_is_done_condition_.NotifyAll();
  }
}


void SociumSacrificeVerifier::Verify() {
  using communication::MessageType::kSociumVerifierSemiMult;
  using communication::MessageType::kSociumVerifierV;
  using communication::MessageType::kSociumVerifierCheckZero;
  using boost::numeric::ublas::matrix;
  
  auto& communication_layer = backend_.GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  //We assume the role of S_i and use the rng shared with S_i+1
  auto& my_rng = 
    backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
  //We assume the role of S_i+1 and use the rng shared with S_i
  auto& previous_rng = 
    backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
  
  size_t const number_of_triples64 = lambdas_i_x64_.size();
  assert(number_of_triples64 == lambdas_i_y64_.size());
  assert(number_of_triples64 == gammas_i_xy64_.size());
  assert(number_of_triples64 == lambdas_i_minus_1_x64_.size());
  assert(number_of_triples64 == lambdas_i_minus_1_y64_.size());
  assert(number_of_triples64 == gammas_i_minus_1_xy64_.size());
  
  size_t const number_of_triples128 = lambdas_i_x128_.size();
  assert(number_of_triples128 == lambdas_i_y128_.size());
  assert(number_of_triples128 == gammas_i_xy128_.size());
  assert(number_of_triples128 == lambdas_i_minus_1_x128_.size());
  assert(number_of_triples128 == lambdas_i_minus_1_y128_.size());
  assert(number_of_triples128 == gammas_i_minus_1_xy128_.size());
  
  size_t const number_of_matrix_triples64 = matrix_lambdas_i_x64_.size();
  assert(number_of_matrix_triples64 == matrix_lambdas_i_y64_.size());
  assert(number_of_matrix_triples64 == matrix_gammas_i_xy64_.size());
  assert(number_of_matrix_triples64 == matrix_lambdas_i_minus_1_x64_.size());
  assert(number_of_matrix_triples64 == matrix_lambdas_i_minus_1_y64_.size());
  assert(number_of_matrix_triples64 == matrix_gammas_i_minus_1_xy64_.size());
  
  size_t const number_of_matrix_triples128 = matrix_lambdas_i_x128_.size();
  assert(number_of_matrix_triples128 == matrix_lambdas_i_y128_.size());
  assert(number_of_matrix_triples128 == matrix_gammas_i_xy128_.size());
  assert(number_of_matrix_triples128 == matrix_lambdas_i_minus_1_x128_.size());
  assert(number_of_matrix_triples128 == matrix_lambdas_i_minus_1_y128_.size());
  assert(number_of_matrix_triples128 == matrix_gammas_i_minus_1_xy128_.size());
  
  size_t const number_of_triples = 
    number_of_triples64 + number_of_triples128;

  size_t const number_of_matrix_triples = 
    number_of_matrix_triples64 + number_of_matrix_triples128;
    
  //If triples are empty, there's nothing to do. 
  if(number_of_triples + number_of_matrix_triples == 0) {
    return;
  }
  
  size_t const number_of_triples64_bytes = 
    number_of_triples64 * sizeof(uint64_t);
  size_t const number_of_triples128_bytes = 
    number_of_triples128 * sizeof(UInt128);
    
  size_t number_of_matrix_u_w64_bytes = 0;
  size_t number_of_matrix_u_v64_bytes = 0;
  for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
    size_t const u = matrix_lambdas_i_x64_[i].size1();
    size_t const w = matrix_lambdas_i_x64_[i].size2();
    size_t const v = matrix_lambdas_i_y64_[i].size2();
    assert(matrix_lambdas_i_x64_[i].size1() == u);
    assert(matrix_lambdas_i_x64_[i].size2() == w);
    assert(matrix_lambdas_i_minus_1_x64_[i].size1() == u);
    assert(matrix_lambdas_i_minus_1_x64_[i].size2() == w);
    assert(matrix_lambdas_i_y64_[i].size1() == w);
    assert(matrix_lambdas_i_y64_[i].size2() == v);
    assert(matrix_lambdas_i_minus_1_y64_[i].size1() == w);
    assert(matrix_lambdas_i_minus_1_y64_[i].size2() == v);
    assert(matrix_gammas_i_xy64_[i].size1() == u);
    assert(matrix_gammas_i_xy64_[i].size2() == v);
    assert(matrix_gammas_i_minus_1_xy64_[i].size1() == u);
    assert(matrix_gammas_i_minus_1_xy64_[i].size2() == v);
    number_of_matrix_u_w64_bytes += u * w * sizeof(uint64_t);
    number_of_matrix_u_v64_bytes += u * v * sizeof(uint64_t);
  }
  
  size_t number_of_matrix_u_w128_bytes = 0;
  size_t number_of_matrix_u_v128_bytes = 0;
  for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
    size_t const u = matrix_lambdas_i_x128_[i].size1();
    size_t const w = matrix_lambdas_i_x128_[i].size2();
    size_t const v = matrix_lambdas_i_y128_[i].size2();
    assert(matrix_lambdas_i_x128_[i].size1() == u);
    assert(matrix_lambdas_i_x128_[i].size2() == w);
    assert(matrix_lambdas_i_minus_1_x128_[i].size1() == u);
    assert(matrix_lambdas_i_minus_1_x128_[i].size2() == w);
    assert(matrix_lambdas_i_y128_[i].size1() == w);
    assert(matrix_lambdas_i_y128_[i].size2() == v);
    assert(matrix_lambdas_i_minus_1_y128_[i].size1() == w);
    assert(matrix_lambdas_i_minus_1_y128_[i].size2() == v);
    assert(matrix_gammas_i_xy128_[i].size1() == u);
    assert(matrix_gammas_i_xy128_[i].size2() == v);
    assert(matrix_gammas_i_minus_1_xy128_[i].size1() == u);
    assert(matrix_gammas_i_minus_1_xy128_[i].size2() == v);
    number_of_matrix_u_w128_bytes += u * w * sizeof(UInt128);
    number_of_matrix_u_v128_bytes += u * v * sizeof(UInt128);
  }
  
  size_t const number_of_triples_bytes = 
    number_of_triples64_bytes + number_of_triples128_bytes;
  size_t const number_of_matrix_u_w_bytes = 
    number_of_matrix_u_w64_bytes + number_of_matrix_u_w128_bytes;
  size_t const number_of_matrix_u_v_bytes = 
    number_of_matrix_u_v64_bytes + number_of_matrix_u_v128_bytes;
  size_t const number_of_rng_bytes = 
    number_of_triples_bytes + number_of_matrix_u_w_bytes 
    + number_of_triples_bytes + number_of_matrix_u_v_bytes 
    + sizeof(UInt128);
    
  size_t const lambda_x64_prime_offset = 0;
  size_t const lambda_x128_prime_offset = 
    lambda_x64_prime_offset + number_of_triples64_bytes;
  size_t const matrix_lambda_x64_prime_offset =
    lambda_x128_prime_offset + number_of_triples128_bytes;
  size_t const matrix_lambda_x128_prime_offset =
    matrix_lambda_x64_prime_offset + number_of_matrix_u_w64_bytes;
  size_t const alpha64_offset = 
    matrix_lambda_x128_prime_offset + number_of_matrix_u_w128_bytes;
  assert(alpha64_offset == number_of_triples_bytes + number_of_matrix_u_w_bytes);
  size_t const alpha128_offset = 
    alpha64_offset + number_of_triples64_bytes;
  size_t const matrix_alpha64_offset =
    alpha128_offset + number_of_triples128_bytes;
  size_t const matrix_alpha128_offset =
    matrix_alpha64_offset + number_of_matrix_u_v64_bytes;
  size_t const r_offset = 
    matrix_alpha128_offset + number_of_matrix_u_v128_bytes;
  assert(r_offset == 2*number_of_triples_bytes 
                     + number_of_matrix_u_w_bytes 
                     + number_of_matrix_u_v_bytes);
  size_t const gamma_x_prime_y64_offset = alpha64_offset;
  size_t const gamma_x_prime_y128_offset = alpha128_offset;
  size_t const matrix_gamma_x_prime_y64_offset = matrix_alpha64_offset;
  size_t const matrix_gamma_x_prime_y128_offset = matrix_alpha128_offset;
  size_t const v64_offset = lambda_x64_prime_offset;
  size_t const v128_offset = lambda_x128_prime_offset;
  size_t const matrix_v64_offset = matrix_lambda_x64_prime_offset;
  size_t const matrix_v128_offset = matrix_lambda_x128_prime_offset;
  size_t const w64_0_offset = 0;
  size_t const w128_0_offset = number_of_triples64_bytes;
  size_t const matrix_w64_0_offset = 
    w128_0_offset + number_of_triples128_bytes;
  size_t const matrix_w128_0_offset = 
    matrix_w64_0_offset + number_of_matrix_u_v64_bytes;
  size_t const w64_1_offset = 
    matrix_w128_0_offset + number_of_matrix_u_v128_bytes;
  size_t const w128_1_offset = 
    w64_1_offset + number_of_triples64_bytes;
  size_t const matrix_w64_1_offset = 
    w128_1_offset + number_of_triples128_bytes;
  size_t const matrix_w128_1_offset = 
    matrix_w64_1_offset + number_of_matrix_u_v64_bytes;
         
  auto AssignToMatrix = [](auto& mat, uint8_t const* data_pointer) {
    using ArithmeticType = typename std::decay_t<decltype(mat)>::value_type;
    size_t offset = 0;
    for(size_t i = 0; i != mat.size1(); ++i) {
      for(size_t j = 0; j != mat.size2(); ++j) {
        ArithmeticType& v = mat(i, j);
        memcpy(&v, data_pointer + offset, sizeof(ArithmeticType));
        offset += sizeof(ArithmeticType);
      }
    }
  };
  
  auto AssignFromMatrix = [](uint8_t* data_pointer, auto const& mat) {
    using ArithmeticType = typename std::decay_t<decltype(mat)>::value_type;
    size_t offset = 0;
    for(size_t i = 0; i != mat.size1(); ++i) {
      for(size_t j = 0; j != mat.size2(); ++j) {
        ArithmeticType const& v = mat(i, j);
        memcpy(data_pointer + offset, &v, sizeof(ArithmeticType));
        offset += sizeof(ArithmeticType);
      }
    }
  };
  
  //rng_bytes contain lambda_x_prime, alpha and r, respectively
  //For lambda_x_prime and alpha, the order is as follows:
  //64-bit, 128-bit, 64-bit matrix, 128-bit matrix
  std::vector<uint8_t> my_id_rng_bytes = 
    my_rng.template GetUnsigned<uint8_t>(gate_id_, number_of_rng_bytes);
  std::vector<uint8_t> previous_id_rng_bytes = 
    previous_rng.template GetUnsigned<uint8_t>(gate_id_, number_of_rng_bytes);
  
  UInt128 my_id_r;
  memcpy(&my_id_r, my_id_rng_bytes.data() + r_offset, sizeof(UInt128));
  UInt128 previous_id_r;
  memcpy(&previous_id_r, previous_id_rng_bytes.data() + r_offset, sizeof(UInt128));
  
  //Calculate gamma_x_prime_y (step 2)
  {
    uint8_t const* const alpha_i_pointer = 
      my_id_rng_bytes.data() + alpha64_offset;
    uint8_t const* const alpha_i_minus_1_pointer = 
      previous_id_rng_bytes.data() + alpha64_offset;
    uint8_t const* const lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + lambda_x64_prime_offset;
    uint8_t const* const lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + lambda_x64_prime_offset;
    uint8_t* const gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + gamma_x_prime_y64_offset;
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples64; ++i) {
      uint64_t alpha_i, alpha_i_minus_1, 
               lambda_i_x_prime, lambda_i_minus_1_x_prime;
      memcpy(&alpha_i, alpha_i_pointer + offset, sizeof(uint64_t));
      memcpy(&alpha_i_minus_1, 
             alpha_i_minus_1_pointer + offset, 
             sizeof(uint64_t));
      memcpy(&lambda_i_x_prime, 
             lambda_i_x_prime_pointer + offset, 
             sizeof(uint64_t));
      memcpy(&lambda_i_minus_1_x_prime, 
             lambda_i_minus_1_x_prime_pointer + offset, 
             sizeof(uint64_t));
      uint64_t lambda_i_y = lambdas_i_y64_[i],
               lambda_i_minus_1_y = lambdas_i_minus_1_y64_[i];
      uint64_t c_i = lambda_i_x_prime * lambda_i_y
                     + lambda_i_x_prime * lambda_i_minus_1_y
                     + lambda_i_minus_1_x_prime * lambda_i_y
                     + alpha_i - alpha_i_minus_1;
      memcpy(gamma_i_x_prime_y_pointer + offset, &c_i, sizeof(uint64_t));
      offset += sizeof(uint64_t);
    }
  }
  
  {
    uint8_t const* const alpha_i_pointer = 
      my_id_rng_bytes.data() + alpha128_offset;
    uint8_t const* const alpha_i_minus_1_pointer = 
      previous_id_rng_bytes.data() + alpha128_offset;
    uint8_t const* const lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + lambda_x128_prime_offset;
    uint8_t const* const lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + lambda_x128_prime_offset;
    uint8_t* const gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + gamma_x_prime_y128_offset;
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples128; ++i) {
      UInt128 alpha_i, alpha_i_minus_1, 
               lambda_i_x_prime, lambda_i_minus_1_x_prime;
      memcpy(&alpha_i, alpha_i_pointer + offset, sizeof(UInt128));
      memcpy(&alpha_i_minus_1, 
             alpha_i_minus_1_pointer + offset, 
             sizeof(UInt128));
      memcpy(&lambda_i_x_prime, 
             lambda_i_x_prime_pointer + offset, 
             sizeof(UInt128));
      memcpy(&lambda_i_minus_1_x_prime, 
             lambda_i_minus_1_x_prime_pointer + offset, 
             sizeof(UInt128));
      UInt128 lambda_i_y = lambdas_i_y128_[i],
              lambda_i_minus_1_y = lambdas_i_minus_1_y128_[i];
      UInt128 c_i = lambda_i_x_prime * lambda_i_y
                     + lambda_i_x_prime * lambda_i_minus_1_y
                     + lambda_i_minus_1_x_prime * lambda_i_y
                     + alpha_i - alpha_i_minus_1;
      memcpy(gamma_i_x_prime_y_pointer + offset, &c_i, sizeof(UInt128));
      offset += sizeof(UInt128);
    }
  }
  
  {
    uint8_t const* const matrix_alpha_i_pointer = 
      my_id_rng_bytes.data() + matrix_alpha64_offset;
    uint8_t const* const matrix_alpha_i_minus_1_pointer = 
      previous_id_rng_bytes.data() + matrix_alpha64_offset;
    uint8_t const* const matrix_lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + matrix_lambda_x64_prime_offset;
    uint8_t const* const matrix_lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + matrix_lambda_x64_prime_offset;
    uint8_t* const matrix_gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + matrix_gamma_x_prime_y64_offset;
    size_t u_w_offset = 0;
    size_t u_v_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
      size_t const u = matrix_lambdas_i_x64_[i].size1();
      size_t const w = matrix_lambdas_i_x64_[i].size2();
      size_t const v = matrix_lambdas_i_y64_[i].size2();
      matrix<uint64_t> matrix_alpha_i(u, v); 
      matrix<uint64_t> matrix_alpha_i_minus_1(u, v); 
      matrix<uint64_t> matrix_lambda_i_x_prime(u, w);
      matrix<uint64_t> matrix_lambda_i_minus_1_x_prime(u, w);
      
      AssignToMatrix(matrix_alpha_i, 
                     matrix_alpha_i_pointer + u_v_offset);
      AssignToMatrix(matrix_alpha_i_minus_1, 
                     matrix_alpha_i_minus_1_pointer + u_v_offset);
      AssignToMatrix(matrix_lambda_i_x_prime, 
                     matrix_lambda_i_x_prime_pointer + u_w_offset);
      AssignToMatrix(matrix_lambda_i_minus_1_x_prime, 
                     matrix_lambda_i_minus_1_x_prime_pointer + u_w_offset);
      auto& matrix_lambda_i_y = matrix_lambdas_i_y64_[i];
      auto& matrix_lambda_i_minus_1_y = matrix_lambdas_i_minus_1_y64_[i];
      matrix<uint64_t> c_i = 
        prod(matrix_lambda_i_x_prime, matrix_lambda_i_y)
        + prod(matrix_lambda_i_x_prime, matrix_lambda_i_minus_1_y)
        + prod(matrix_lambda_i_minus_1_x_prime, matrix_lambda_i_y)
        + matrix_alpha_i - matrix_alpha_i_minus_1;
      AssignFromMatrix(matrix_gamma_i_x_prime_y_pointer + u_v_offset, c_i);
      u_w_offset += u * w * sizeof(uint64_t);
      u_v_offset += u * v * sizeof(uint64_t);
    }
  }
  
  {
    uint8_t const* const matrix_alpha_i_pointer = 
      my_id_rng_bytes.data() + matrix_alpha128_offset;
    uint8_t const* const matrix_alpha_i_minus_1_pointer = 
      previous_id_rng_bytes.data() + matrix_alpha128_offset;
    uint8_t const* const matrix_lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + matrix_lambda_x128_prime_offset;
    uint8_t const* const matrix_lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + matrix_lambda_x128_prime_offset;
    uint8_t* const matrix_gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + matrix_gamma_x_prime_y128_offset;
    size_t u_w_offset = 0;
    size_t u_v_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
      size_t const u = matrix_lambdas_i_x128_[i].size1();
      size_t const w = matrix_lambdas_i_x128_[i].size2();
      size_t const v = matrix_lambdas_i_y128_[i].size2();
      matrix<UInt128> matrix_alpha_i(u, v); 
      matrix<UInt128> matrix_alpha_i_minus_1(u, v); 
      matrix<UInt128> matrix_lambda_i_x_prime(u, w);
      matrix<UInt128> matrix_lambda_i_minus_1_x_prime(u, w);
      
      AssignToMatrix(matrix_alpha_i, 
                     matrix_alpha_i_pointer + u_v_offset);
      AssignToMatrix(matrix_alpha_i_minus_1, 
                     matrix_alpha_i_minus_1_pointer + u_v_offset);
      AssignToMatrix(matrix_lambda_i_x_prime, 
                     matrix_lambda_i_x_prime_pointer + u_w_offset);
      AssignToMatrix(matrix_lambda_i_minus_1_x_prime, 
                     matrix_lambda_i_minus_1_x_prime_pointer + u_w_offset);
      auto& matrix_lambda_i_y = matrix_lambdas_i_y128_[i];
      auto& matrix_lambda_i_minus_1_y = matrix_lambdas_i_minus_1_y128_[i];
      matrix<UInt128> c_i = 
        prod(matrix_lambda_i_x_prime, matrix_lambda_i_y)
        + prod(matrix_lambda_i_x_prime, matrix_lambda_i_minus_1_y)
        + prod(matrix_lambda_i_minus_1_x_prime, matrix_lambda_i_y)
        + matrix_alpha_i - matrix_alpha_i_minus_1;
      AssignFromMatrix(matrix_gamma_i_x_prime_y_pointer + u_v_offset, c_i);
      u_w_offset += u * w * sizeof(UInt128);
      u_v_offset += u * v * sizeof(UInt128);
    }
  }
  
  //Send my_id_gamma_x_prime_y to next_id 
  if (my_id == 2) { // We have a 3-additive sharing and need 2-additive between S0, S1, so just let S2 send to S0
    auto payload = std::span<uint8_t const>(
      my_id_rng_bytes.data() + gamma_x_prime_y64_offset, number_of_triples_bytes + number_of_matrix_u_v_bytes);
    auto message = 
      communication::BuildMessage(kSociumVerifierSemiMult, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }

  //Get previous_id_gamma_x_prime_y
  if (my_id == 0) {
    auto message = semi_mult_future_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    assert(payload->size() == number_of_triples_bytes + number_of_matrix_u_v_bytes);
    memcpy(previous_id_rng_bytes.data() + gamma_x_prime_y64_offset,
           payload->Data(),
           number_of_triples_bytes + number_of_matrix_u_v_bytes);
  }

  // S2 is excluded from remaining check
  if (my_id == 2) {
    return;
  }
  
  // Sample r
  UInt128 r128 = 0;
  if (my_id == 0) {
    auto& r_rng = backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
    r128 = r_rng.template GetUnsigned<UInt128>(gate_id_, 1)[0];
  } else if (my_id == 1) {
    auto& r_rng = backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
    r128 = r_rng.template GetUnsigned<UInt128>(gate_id_, 1)[0];
  }
  uint64_t r64 = uint64_t(r128);
  
  //Calculate v

  if (my_id == 0) {
    uint8_t* lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + lambda_x64_prime_offset;
    uint8_t* lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + lambda_x64_prime_offset;
    //We overwrite the lambda_x' values with v
    uint8_t* v_i_pointer = lambda_i_x_prime_pointer;
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples64; ++i) {
      uint64_t lambda_i_x_prime, lambda_i_minus_1_x_prime;
      memcpy(&lambda_i_x_prime, 
             lambda_i_x_prime_pointer + offset, 
             sizeof(uint64_t));
      memcpy(&lambda_i_minus_1_x_prime, 
             lambda_i_minus_1_x_prime_pointer + offset, 
             sizeof(uint64_t));
      uint64_t lambda_i_x = lambdas_i_x64_[i];
      uint64_t lambda_i_minus_1_x = lambdas_i_minus_1_x64_[i];
      // Internal conversion from replicated to additive between S0, S1
      // by S0 adding up the shares from S0, S2 and S1 keeping its own shares
      uint64_t v_i = r64 * (lambda_i_x + lambda_i_minus_1_x) - (lambda_i_x_prime + lambda_i_minus_1_x_prime);
      memcpy(v_i_pointer + offset, &v_i, sizeof(uint64_t));
      offset += sizeof(uint64_t);
    }
  } else if (my_id == 1) {
    uint8_t* lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + lambda_x64_prime_offset;
    //We overwrite the lambda_x' values with v
    uint8_t* v_i_pointer = lambda_i_x_prime_pointer;
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples64; ++i) {
      uint64_t lambda_i_x_prime;
      memcpy(&lambda_i_x_prime, 
             lambda_i_x_prime_pointer + offset, 
             sizeof(uint64_t));
      uint64_t lambda_i_x = lambdas_i_x64_[i];
      // Internal conversion from replicated to additive between S0, S1
      // by S0 adding up the shares from S0, S2 and S1 keeping its own shares
      uint64_t v_i = r64 * (lambda_i_x) - (lambda_i_x_prime);
      memcpy(v_i_pointer + offset, &v_i, sizeof(uint64_t));
      offset += sizeof(uint64_t);
    }
  }

  if (my_id == 0) {
    uint8_t* lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + lambda_x128_prime_offset;
    uint8_t* lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + lambda_x128_prime_offset;
    //We overwrite the lambda_x' values with v
    uint8_t* v_i_pointer = lambda_i_x_prime_pointer;
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples128; ++i) {
      UInt128 lambda_i_x_prime, lambda_i_minus_1_x_prime;
      memcpy(&lambda_i_x_prime, 
             lambda_i_x_prime_pointer + offset, 
             sizeof(UInt128));
      memcpy(&lambda_i_minus_1_x_prime, 
             lambda_i_minus_1_x_prime_pointer + offset, 
             sizeof(UInt128));
      UInt128 lambda_i_x = lambdas_i_x128_[i];
      UInt128 lambda_i_minus_1_x = lambdas_i_minus_1_x128_[i];
      // Internal conversion from replicated to additive between S0, S1
      // by S0 adding up the shares from S0, S2 and S1 keeping its own shares
      UInt128 v_i = r128 * (lambda_i_x + lambda_i_minus_1_x) - (lambda_i_x_prime + lambda_i_minus_1_x_prime);
      memcpy(v_i_pointer + offset, &v_i, sizeof(r128));
      offset += sizeof(r128);
    }
  } else if (my_id == 1) {
    uint8_t* lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + lambda_x128_prime_offset;
    //We overwrite the lambda_x' values with v
    uint8_t* v_i_pointer = lambda_i_x_prime_pointer;
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples128; ++i) {
      UInt128 lambda_i_x_prime;
      memcpy(&lambda_i_x_prime, 
             lambda_i_x_prime_pointer + offset, 
             sizeof(UInt128));
      UInt128 lambda_i_x = lambdas_i_x128_[i];
      // Internal conversion from replicated to additive between S0, S1
      // by S0 adding up the shares from S0, S2 and S1 keeping its own shares
      UInt128 v_i = r128 * (lambda_i_x) - (lambda_i_x_prime);
      memcpy(v_i_pointer + offset, &v_i, sizeof(r128));
      offset += sizeof(r128);
    }
  }

  if (my_id == 0) {
    uint8_t* matrix_lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + matrix_lambda_x64_prime_offset;
    uint8_t* matrix_lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + matrix_lambda_x64_prime_offset;
    //We overwrite the lambda_x' values with v
    uint8_t* v_i_pointer = matrix_lambda_i_x_prime_pointer;
    size_t u_w_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
      size_t const u = matrix_lambdas_i_x64_[i].size1();
      size_t const w = matrix_lambdas_i_x64_[i].size2();
      matrix<uint64_t> matrix_lambda_i_x_prime(u, w); 
      matrix<uint64_t> matrix_lambda_i_minus_1_x_prime(u, w);
      AssignToMatrix(matrix_lambda_i_x_prime, 
                     matrix_lambda_i_x_prime_pointer + u_w_offset);
      AssignToMatrix(matrix_lambda_i_minus_1_x_prime, 
                     matrix_lambda_i_minus_1_x_prime_pointer + u_w_offset);
      auto& matrix_lambda_i_x = matrix_lambdas_i_x64_[i];
      auto& matrix_lambda_i_minus_1_x = matrix_lambdas_i_minus_1_x64_[i];
      // Internal conversion from replicated to additive between S0, S1
      // by S0 adding up the shares from S0, S2 and S1 keeping its own shares
      matrix<uint64_t> matrix_v = 
        r64 * (matrix_lambda_i_x + matrix_lambda_i_minus_1_x) - (matrix_lambda_i_x_prime + matrix_lambda_i_minus_1_x_prime);
      AssignFromMatrix(v_i_pointer + u_w_offset, matrix_v);
      u_w_offset += u * w * sizeof(uint64_t);
    }
  } else if (my_id == 1) {
    uint8_t* matrix_lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + matrix_lambda_x64_prime_offset;
    //We overwrite the lambda_x' values with v
    uint8_t* v_i_pointer = matrix_lambda_i_x_prime_pointer;
    size_t u_w_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
      size_t const u = matrix_lambdas_i_x64_[i].size1();
      size_t const w = matrix_lambdas_i_x64_[i].size2();
      matrix<uint64_t> matrix_lambda_i_x_prime(u, w);
      AssignToMatrix(matrix_lambda_i_x_prime, 
                     matrix_lambda_i_x_prime_pointer + u_w_offset);
      auto& matrix_lambda_i_x = matrix_lambdas_i_x64_[i];
      // Internal conversion from replicated to additive between S0, S1
      // by S0 adding up the shares from S0, S2 and S1 keeping its own shares
      matrix<uint64_t> matrix_v = 
        r64 * (matrix_lambda_i_x) - (matrix_lambda_i_x_prime);
      AssignFromMatrix(v_i_pointer + u_w_offset, matrix_v);
      u_w_offset += u * w * sizeof(uint64_t);
    }
  }

  if (my_id == 0) {
    uint8_t* matrix_lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + matrix_lambda_x128_prime_offset;
    uint8_t* matrix_lambda_i_minus_1_x_prime_pointer = 
      previous_id_rng_bytes.data() + matrix_lambda_x128_prime_offset;
    //We overwrite the lambda_x' values with v
    uint8_t* v_i_pointer = matrix_lambda_i_x_prime_pointer;
    size_t u_w_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
      size_t const u = matrix_lambdas_i_x128_[i].size1();
      size_t const w = matrix_lambdas_i_x128_[i].size2();
      matrix<UInt128> matrix_lambda_i_x_prime(u, w); 
      matrix<UInt128> matrix_lambda_i_minus_1_x_prime(u, w);
      AssignToMatrix(matrix_lambda_i_x_prime, 
                     matrix_lambda_i_x_prime_pointer + u_w_offset);
      AssignToMatrix(matrix_lambda_i_minus_1_x_prime, 
                     matrix_lambda_i_minus_1_x_prime_pointer + u_w_offset);
      auto& matrix_lambda_i_x = matrix_lambdas_i_x128_[i];
      auto& matrix_lambda_i_minus_1_x = matrix_lambdas_i_minus_1_x128_[i];
      // Internal conversion from replicated to additive between S0, S1
      // by S0 adding up the shares from S0, S2 and S1 keeping its own shares
      matrix<UInt128> matrix_v = 
        r128 * (matrix_lambda_i_x + matrix_lambda_i_minus_1_x) - (matrix_lambda_i_x_prime + matrix_lambda_i_minus_1_x_prime);
      AssignFromMatrix(v_i_pointer + u_w_offset, matrix_v);
      u_w_offset += u * w * sizeof(UInt128);
    }
  } else if (my_id == 1) {
    uint8_t* matrix_lambda_i_x_prime_pointer = 
      my_id_rng_bytes.data() + matrix_lambda_x128_prime_offset;
    //We overwrite the lambda_x' values with v
    uint8_t* v_i_pointer = matrix_lambda_i_x_prime_pointer;
    size_t u_w_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
      size_t const u = matrix_lambdas_i_x128_[i].size1();
      size_t const w = matrix_lambdas_i_x128_[i].size2();
      matrix<UInt128> matrix_lambda_i_x_prime(u, w);
      AssignToMatrix(matrix_lambda_i_x_prime, 
                     matrix_lambda_i_x_prime_pointer + u_w_offset);
      auto& matrix_lambda_i_x = matrix_lambdas_i_x128_[i];
      // Internal conversion from replicated to additive between S0, S1
      // by S0 adding up the shares from S0, S2 and S1 keeping its own shares
      matrix<UInt128> matrix_v = 
        r128 * (matrix_lambda_i_x) - (matrix_lambda_i_x_prime);
      AssignFromMatrix(v_i_pointer + u_w_offset, matrix_v);
      u_w_offset += u * w * sizeof(UInt128);
    }
  }

  //v is now where lambda_x' was
  
  //Restore v
  
  std::span<uint8_t const> payload(
    previous_id_rng_bytes.data() + v64_offset, 
    number_of_triples_bytes + number_of_matrix_u_w_bytes);
  auto message = 
    communication::BuildMessage(kSociumVerifierV, gate_id_, payload);
  if (my_id == 0) {
    //Send to S1
    communication_layer.SendMessage(next_id, message.Release());
  } else if (my_id == 1) {
    //Send to S0
    communication_layer.SendMessage(previous_id, message.Release());
  }
  
  std::vector<uint8_t> next_id_v_bytes;
  next_id_v_bytes.reserve(number_of_triples_bytes + number_of_matrix_u_w_bytes);
  {
    //Receive v share from other party
    auto message = v_future_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    assert(payload->size() == number_of_triples_bytes + number_of_matrix_u_w_bytes);
    next_id_v_bytes.insert(
      next_id_v_bytes.end(), payload->Data(), payload->Data() + payload->size());
  }
  
  //Calculate w
  std::vector<uint8_t> w_bytes(2 * (number_of_triples_bytes + number_of_matrix_u_v_bytes));
  {
    uint8_t* v_i_pointer = my_id_rng_bytes.data() + v64_offset;
    uint8_t* v_i_plus_1_pointer = next_id_v_bytes.data() + v64_offset;
    uint8_t* gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + gamma_x_prime_y64_offset;
    uint8_t* gamma_i_minus_1_x_prime_y_pointer = 
      previous_id_rng_bytes.data() + gamma_x_prime_y64_offset;
    std::array<uint8_t*, 2> w_pointers{
      w_bytes.data() + w64_0_offset,
      w_bytes.data() + w64_1_offset
    };
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples64; ++i) {
      uint64_t v_i, v_i_plus_1, gamma_i_x_prime_y, gamma_i_minus_1_x_prime_y;
      memcpy(&v_i, v_i_pointer + offset, sizeof(uint64_t));
      memcpy(&v_i_plus_1, v_i_plus_1_pointer + offset, sizeof(uint64_t));
      memcpy(&gamma_i_x_prime_y, 
             gamma_i_x_prime_y_pointer + offset, 
             sizeof(uint64_t));
      memcpy(&gamma_i_minus_1_x_prime_y, 
             gamma_i_minus_1_x_prime_y_pointer + offset, 
             sizeof(uint64_t));
      uint64_t lambda_i_y = lambdas_i_y64_[i];
      uint64_t lambda_i_minus_1_y = lambdas_i_minus_1_y64_[i];
      uint64_t gamma_i_xy = gammas_i_xy64_[i];
      uint64_t gamma_i_minus_1_xy = gammas_i_minus_1_xy64_[i];
      uint64_t v = v_i + v_i_plus_1; // i_plus_1 represents 0 for i=1 here!
      // Internal conversion from replicated to additive between S0, S1
      // by S0 adding up the shares from S0, S2 and S1 keeping its own shares
      uint64_t w_i = 0;
      if (my_id == 0) {
        w_i = v * (lambda_i_y + lambda_i_minus_1_y) - r64 * (gamma_i_xy + gamma_i_minus_1_xy)
                      + (gamma_i_x_prime_y + gamma_i_minus_1_x_prime_y);
      } else if (my_id == 1) {
        w_i = v * (lambda_i_y) - r64 * (gamma_i_xy)
                      + (gamma_i_x_prime_y);
      } else {
        assert(false);
      }
      uint64_t w_i_other = -w_i;
      memcpy(w_pointers[my_id] + offset, &w_i, sizeof(uint64_t));
      memcpy(w_pointers[1 - my_id] + offset, &w_i_other, sizeof(uint64_t));
      offset += sizeof(uint64_t);
    }
  }

  {
    uint8_t* v_i_pointer = my_id_rng_bytes.data() + v128_offset;
    uint8_t* v_i_plus_1_pointer = next_id_v_bytes.data() + v128_offset;
    uint8_t* gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + gamma_x_prime_y128_offset;
    uint8_t* gamma_i_minus_1_x_prime_y_pointer = 
      previous_id_rng_bytes.data() + gamma_x_prime_y128_offset;
    std::array<uint8_t*, 2> w_pointers{
      w_bytes.data() + w128_0_offset,
      w_bytes.data() + w128_1_offset
    };
    size_t offset = 0;
    for(size_t i = 0; i != number_of_triples128; ++i) {
      UInt128 v_i, v_i_plus_1, gamma_i_x_prime_y, gamma_i_minus_1_x_prime_y;
      memcpy(&v_i, v_i_pointer + offset, sizeof(UInt128));
      memcpy(&v_i_plus_1, v_i_plus_1_pointer + offset, sizeof(UInt128));
      memcpy(&gamma_i_x_prime_y, 
             gamma_i_x_prime_y_pointer + offset, 
             sizeof(UInt128));
      memcpy(&gamma_i_minus_1_x_prime_y, 
             gamma_i_minus_1_x_prime_y_pointer + offset, 
             sizeof(UInt128));
      UInt128 lambda_i_y = lambdas_i_y128_[i];
      UInt128 lambda_i_minus_1_y = lambdas_i_minus_1_y128_[i];
      UInt128 gamma_i_xy = gammas_i_xy128_[i];
      UInt128 gamma_i_minus_1_xy = gammas_i_minus_1_xy128_[i];
      UInt128 v = v_i + v_i_plus_1; // i_plus_1 represents 0 for i=1 here!
      // Internal conversion from replicated to additive between S0, S1
      // by S0 adding up the shares from S0, S2 and S1 keeping its own shares
      UInt128 w_i = 0;
      if (my_id == 0) {
        w_i = v * (lambda_i_y + lambda_i_minus_1_y) - r128 * (gamma_i_xy + gamma_i_minus_1_xy)
                      + (gamma_i_x_prime_y + gamma_i_minus_1_x_prime_y);
      } else if (my_id == 1) {
        w_i = v * (lambda_i_y) - r128 * (gamma_i_xy)
                      + (gamma_i_x_prime_y);
      } else {
        assert(false);
      }
      UInt128 w_i_other = -w_i;
      memcpy(w_pointers[my_id] + offset, &w_i, sizeof(UInt128));
      memcpy(w_pointers[1 - my_id] + offset, &w_i_other, sizeof(UInt128));
      offset += sizeof(UInt128);
    }
  }

  {
    uint8_t* matrix_v_i_pointer = my_id_rng_bytes.data() + matrix_v64_offset;
    uint8_t* matrix_v_i_plus_1_pointer = next_id_v_bytes.data() + matrix_v64_offset;
    uint8_t* matrix_gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + matrix_gamma_x_prime_y64_offset;
    uint8_t* matrix_gamma_i_minus_1_x_prime_y_pointer = 
      previous_id_rng_bytes.data() + matrix_gamma_x_prime_y64_offset;
    std::array<uint8_t*, 2> matrix_w_pointers{
      w_bytes.data() + matrix_w64_0_offset,
      w_bytes.data() + matrix_w64_1_offset
    };
    size_t u_w_offset = 0;
    size_t u_v_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
      size_t const u = matrix_lambdas_i_x64_[i].size1();
      size_t const w = matrix_lambdas_i_x64_[i].size2();
      size_t const v = matrix_lambdas_i_y64_[i].size2();
      matrix<uint64_t> matrix_v(u, w);
      matrix<uint64_t> matrix_gamma_i_x_prime_y(u, v);
      matrix<uint64_t> matrix_gamma_i_minus_1_x_prime_y(u, v);

      AssignToMatrix(matrix_v, matrix_v_i_pointer + u_w_offset);
      {
        matrix<uint64_t> matrix_v_tmp(u, w);
        AssignToMatrix(matrix_v_tmp, matrix_v_i_plus_1_pointer + u_w_offset);
        matrix_v += matrix_v_tmp; // i_plus_1 represents 0 for i=1 here!
      }
      
      AssignToMatrix(matrix_gamma_i_x_prime_y, 
                     matrix_gamma_i_x_prime_y_pointer + u_v_offset);
      AssignToMatrix(matrix_gamma_i_minus_1_x_prime_y, 
                     matrix_gamma_i_minus_1_x_prime_y_pointer + u_v_offset);
                     
      auto& matrix_lambda_i_y = matrix_lambdas_i_y64_[i];
      auto& matrix_lambda_i_minus_1_y = matrix_lambdas_i_minus_1_y64_[i];
      auto& matrix_gamma_i_xy = matrix_gammas_i_xy64_[i];
      auto& matrix_gamma_i_minus_1_xy = matrix_gammas_i_minus_1_xy64_[i];
      // Internal conversion from replicated to additive between S0, S1
      // by S0 adding up the shares from S0, S2 and S1 keeping its own shares
      matrix<uint64_t> matrix_w_i;
      if (my_id == 0) {
        matrix_w_i = 
          prod(matrix_v, (matrix_lambda_i_y + matrix_lambda_i_minus_1_y)) 
          - r64 * (matrix_gamma_i_xy + matrix_gamma_i_minus_1_xy) 
          + (matrix_gamma_i_x_prime_y + matrix_gamma_i_minus_1_x_prime_y);
      } else if (my_id == 1) {
        matrix_w_i = 
          prod(matrix_v, (matrix_lambda_i_y)) 
          - r64 * (matrix_gamma_i_xy) 
          + (matrix_gamma_i_x_prime_y);
      }
      
      matrix<uint64_t> matrix_w_i_other = -matrix_w_i;
      AssignFromMatrix(matrix_w_pointers[my_id] + u_v_offset, matrix_w_i);
      AssignFromMatrix(matrix_w_pointers[1 - my_id] + u_v_offset, matrix_w_i_other);
      u_w_offset += u * w * sizeof(uint64_t);
      u_v_offset += u * v * sizeof(uint64_t);
    }
  }

  {
    uint8_t* matrix_v_i_pointer = my_id_rng_bytes.data() + matrix_v128_offset;
    uint8_t* matrix_v_i_plus_1_pointer = next_id_v_bytes.data() + matrix_v128_offset;
    uint8_t* matrix_gamma_i_x_prime_y_pointer = 
      my_id_rng_bytes.data() + matrix_gamma_x_prime_y128_offset;
    uint8_t* matrix_gamma_i_minus_1_x_prime_y_pointer = 
      previous_id_rng_bytes.data() + matrix_gamma_x_prime_y128_offset;
    std::array<uint8_t*, 2> matrix_w_pointers{
      w_bytes.data() + matrix_w128_0_offset,
      w_bytes.data() + matrix_w128_1_offset
    };
    size_t u_w_offset = 0;
    size_t u_v_offset = 0;
    for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
      size_t const u = matrix_lambdas_i_x128_[i].size1();
      size_t const w = matrix_lambdas_i_x128_[i].size2();
      size_t const v = matrix_lambdas_i_y128_[i].size2();
      matrix<UInt128> matrix_v(u, w);
      matrix<UInt128> matrix_gamma_i_x_prime_y(u, v);
      matrix<UInt128> matrix_gamma_i_minus_1_x_prime_y(u, v);

      AssignToMatrix(matrix_v, matrix_v_i_pointer + u_w_offset);
      {
        matrix<UInt128> matrix_v_tmp(u, w);
        AssignToMatrix(matrix_v_tmp, matrix_v_i_plus_1_pointer + u_w_offset);
        matrix_v += matrix_v_tmp; // i_plus_1 represents 0 for i=1 here!
      }
      
      AssignToMatrix(matrix_gamma_i_x_prime_y, 
                     matrix_gamma_i_x_prime_y_pointer + u_v_offset);
      AssignToMatrix(matrix_gamma_i_minus_1_x_prime_y, 
                     matrix_gamma_i_minus_1_x_prime_y_pointer + u_v_offset);
                     
      auto& matrix_lambda_i_y = matrix_lambdas_i_y128_[i];
      auto& matrix_lambda_i_minus_1_y = matrix_lambdas_i_minus_1_y128_[i];
      auto& matrix_gamma_i_xy = matrix_gammas_i_xy128_[i];
      auto& matrix_gamma_i_minus_1_xy = matrix_gammas_i_minus_1_xy128_[i];
      // Internal conversion from replicated to additive between S0, S1
      // by S0 adding up the shares from S0, S2 and S1 keeping its own shares
      matrix<UInt128> matrix_w_i;
      if (my_id == 0) {
        matrix_w_i = 
          prod(matrix_v, (matrix_lambda_i_y + matrix_lambda_i_minus_1_y)) 
          - r128 * (matrix_gamma_i_xy + matrix_gamma_i_minus_1_xy) 
          + (matrix_gamma_i_x_prime_y + matrix_gamma_i_minus_1_x_prime_y);
      } else if (my_id == 1) {
        matrix_w_i = 
          prod(matrix_v, (matrix_lambda_i_y)) 
          - r128 * (matrix_gamma_i_xy) 
          + (matrix_gamma_i_x_prime_y);
      }
      
      matrix<UInt128> matrix_w_i_other = -matrix_w_i;
      AssignFromMatrix(matrix_w_pointers[my_id] + u_v_offset, matrix_w_i);
      AssignFromMatrix(matrix_w_pointers[1 - my_id] + u_v_offset, matrix_w_i_other);
      u_w_offset += u * w * sizeof(UInt128);
      u_v_offset += u * v * sizeof(UInt128);
    }
  }
  
  //Now we run CheckZero
  std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
  Blake2b(w_bytes.data(), hash.data(), w_bytes.size());

  if (my_id == 0) {
    {
      auto message = communication::BuildMessage(kSociumVerifierCheckZero, gate_id_, hash);
      communication_layer.SendMessage(next_id, message.Release());
    }
  } else if (my_id == 1) {  
    auto message = check_zero_future_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    std::vector<uint8_t> previous_id_received_hash(
      payload->Data(), payload->Data() + payload->size());
    assert(hash.size() == previous_id_received_hash.size());
    for(size_t i = 0; i != hash.size(); ++i) {
      if(hash[i] != previous_id_received_hash[i]) {
        Abort();
      }
    }
  }
}

}  // namespace encrypto::motion