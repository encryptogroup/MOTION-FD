#include <mutex>
#include <type_traits>

#include "base/backend.h"
#include "swift_gate.h"
#include "swift_wire.h"
#include "protocols/share_wrapper.h"
#include "communication/message_manager.h"
#include "utility/helpers.h"
#include "utility/z2_integer.h"
#include "primitives/sharing_randomness_generator.h"
#include "primitives/blake2b.h"

#include <iostream>
#include <fstream>
#include <string>
#include <mutex>
#include <boost/numeric/ublas/io.hpp>

using namespace std::string_literals;
using std::to_string;

using namespace boost::numeric;

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

namespace encrypto::motion::proto::swift {
using std::to_string;

template <typename T>
InputGate<T>::InputGate(std::vector<T> input, std::size_t input_owner, Backend& backend)
    : Base(backend) {
  using communication::MessageType::kSwiftInputGate;
  input_owner_id_ = input_owner;

  uint64_t my_id = GetCommunicationLayer().GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  size_t number_of_simd_values = input.size();
  
  assert(input_owner_id_ >= 0);
  if(my_id != uint64_t(input_owner_id_)) {
    output_wires_ = 
      {GetRegister().template EmplaceWire<swift::Wire<T>>(backend_, number_of_simd_values)};
  } else {
    output_wires_ = 
      {GetRegister().template EmplaceWire<swift::Wire<T>>(
        backend_, number_of_simd_values, std::move(input), std::vector<T>{}, std::vector<T>{})};
  }

  if(my_id != uint64_t(input_owner_id_)) {
    input_future_ = 
      GetCommunicationLayer().GetMessageManager().RegisterReceive(
        input_owner_id_, kSwiftInputGate, gate_id_);
  }
  
  auto input_hash_verifier = backend_.GetSwiftInputHashVerifier();
  if(next_id == uint64_t(input_owner_id_)) {
    //We are S_i-1 so we reserve memory for hash input that we will send to previous_id (S_i+1)
    verifier_hash_data_ = 
      input_hash_verifier->ReserveHashMessage(
        number_of_simd_values * sizeof(T), previous_id);
  }
  if(previous_id == uint64_t(input_owner_id_)) {
    //We are S_i+1 so we reserve memory for hash we will receive from next_id (S_i-1)
    verifier_hash_data_ = 
      input_hash_verifier->ReserveHashCheck(
        number_of_simd_values * sizeof(T), next_id);
  }
}

template <typename T>
void InputGate<T>::EvaluateSetup() {
  uint64_t my_id = GetCommunicationLayer().GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  assert(input_owner_id_ >= 0);
  assert(uint64_t(input_owner_id_) == my_id || 
         uint64_t(input_owner_id_) == next_id || 
         uint64_t(input_owner_id_) == previous_id);
  GetBaseProvider().WaitSetup();

  auto out_wire = std::dynamic_pointer_cast<swift::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto& out_data = out_wire->GetMutableData();
  size_t number_of_simd_values = out_wire->GetNumberOfSimdValues();
  
  if(my_id == uint64_t(input_owner_id_)) {
    //We are S_i here
    //We use the rng we share with S_i+1 to sample lambda_i
    auto& rng_i = GetBaseProvider().GetMyRandomnessGenerator(next_id);
    //We use the rng we share with S_i-1 to sample lambda_i-1
    auto& rng_i_minus_1 = GetBaseProvider().GetMyRandomnessGenerator(previous_id);
    auto& rng_i_plus_1 = GetBaseProvider().GetGlobalRandomnessGenerator();
    out_data.lambda_my_id = rng_i.template GetUnsigned<T>(gate_id_, number_of_simd_values);
    out_data.lambda_previous_id = rng_i_minus_1.template GetUnsigned<T>(gate_id_, number_of_simd_values);
    auto lambda_i_plus_1 = rng_i_plus_1.template GetUnsigned<T>(gate_id_, number_of_simd_values);
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      T lambda = lambda_i_plus_1[i] + out_data.lambda_my_id[i] + out_data.lambda_previous_id[i];
      out_data.values[i] -= lambda;
    }
  } else if(next_id == uint64_t(input_owner_id_)) {
    //We are S_i-1 here
    //We use the rng we share with S_i, since we will generate their lambda_i-1
    auto& rng_i_minus_1 = GetBaseProvider().GetTheirRandomnessGenerator(input_owner_id_);
    auto& rng_i_plus_1 = GetBaseProvider().GetGlobalRandomnessGenerator();
    //Since we are S_i-1 here, lambda_i-1 corresponds to our id
    out_data.lambda_my_id = rng_i_minus_1.template GetUnsigned<T>(gate_id_, number_of_simd_values);
    //Since there are exactly 3 parties, lambda_i-2 = lambda_i+1
    out_data.lambda_previous_id = rng_i_plus_1.template GetUnsigned<T>(gate_id_, number_of_simd_values);
  } else if(previous_id == uint64_t(input_owner_id_)) {
    //We are S_i+1 here
    //We use the rng we share with S_i, since we will generate their lambda_i
    auto& rng_i = GetBaseProvider().GetTheirRandomnessGenerator(input_owner_id_);
    auto& rng_i_plus_1 = GetBaseProvider().GetGlobalRandomnessGenerator();
    //Since we are S_i+1 here, lambda_i+1 corresponds to our id
    out_data.lambda_my_id = rng_i_plus_1.template GetUnsigned<T>(gate_id_, number_of_simd_values);
    out_data.lambda_previous_id = rng_i.template GetUnsigned<T>(gate_id_, number_of_simd_values);
  } else {
    assert(false);
  }
  assert(out_data.lambda_my_id.size() == number_of_simd_values);
  assert(out_data.lambda_previous_id.size() == number_of_simd_values);
  
  out_wire->SetSetupIsReady();
}

template <typename T>
void InputGate<T>::EvaluateOnline() {
  using communication::MessageType::kSwiftInputGate;
  WaitSetup();
  assert(setup_is_ready_);

  auto out_wire = std::dynamic_pointer_cast<swift::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto& out_data = out_wire->GetMutableData();

  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  
  assert(input_owner_id_ >= 0);
  if(my_id == uint64_t(input_owner_id_)) {
    auto payload = ToByteVector<T>(out_data.values);
    auto message = communication::BuildMessage(kSwiftInputGate, gate_id_, payload);
  
    communication_layer.BroadcastMessage(message.Release());
  } else {
    const auto message = input_future_.get();
    const auto payload = communication::GetMessage(message.data())->payload();
    out_data.values = FromByteVector<T>({payload->Data(), payload->size()});
    
    auto input_hash_verifier = backend_.GetSwiftInputHashVerifier();
    verifier_hash_data_.AssignData(out_data.values);
    if(next_id == uint64_t(input_owner_id_)) {
      //We are S_i-1 so we are the one sending the hash to S_i+1
      input_hash_verifier->SetReady();
    }
    else if(previous_id == uint64_t(input_owner_id_)) {
      //We are S_i+1 so we check with the hash we receive from S_i-1
      input_hash_verifier->SetReady();
      input_hash_verifier->GetIsReadyCondition().Wait();
    }
    else {
      assert(false);
    }
  }
}

template class InputGate<std::uint8_t>;
template class InputGate<std::uint16_t>;
template class InputGate<std::uint32_t>;
template class InputGate<std::uint64_t>;

template <typename T>
OutputGate<T>::OutputGate(swift::WirePointer<T> const& parent, std::size_t output_owner)
    : Base(parent->GetBackend()) {
  assert(parent);

  uint64_t my_id = static_cast<std::int64_t>(GetCommunicationLayer().GetMyId());
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;

  size_t number_of_simd_values = parent->GetNumberOfSimdValues();
  parent_ = {std::move(parent)};
  output_owner_ = output_owner;

  output_wires_ = 
    {GetRegister().template EmplaceWire<swift::Wire<T>>(backend_, number_of_simd_values)};

  assert(output_owner_ >= 0);
  if (uint64_t(output_owner_) == my_id || uint64_t(output_owner_) == kAll) {
    lambda_i_plus_1_future_ = 
      GetCommunicationLayer().GetMessageManager().RegisterReceive(
        previous_id, communication::MessageType::kSwiftOutputGate, gate_id_);
  }
  
  auto output_hash_verifier = backend_.GetSwiftOutputHashVerifier();
  if(uint64_t(output_owner_) == previous_id || uint64_t(output_owner_) == kAll) {
    //We assume the role of S_i+1 so we reserve memory for hash that we will send to next_id (S_i)
    verifier_message_hash_data_ = 
      output_hash_verifier->ReserveHashMessage(
        number_of_simd_values * sizeof(T), previous_id);
  }
  if(uint64_t(output_owner_) == my_id || uint64_t(output_owner_) == kAll) {
    //We assume the role of S_i so we reserve memory for hash that we will receive from next_id (S_i+1)
    verifier_check_hash_data_ = 
      output_hash_verifier->ReserveHashCheck(
        number_of_simd_values * sizeof(T), next_id);
  }
}

template <typename T>
void OutputGate<T>::EvaluateSetup() {}

template <typename T>
void OutputGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  parent_[0]->GetIsReadyCondition().Wait();
  size_t number_of_simd_values = parent_[0]->GetNumberOfSimdValues();
  auto in_wire = std::dynamic_pointer_cast<swift::Wire<T>>(parent_[0]);
  assert(in_wire);
  auto& in_data = in_wire->GetMutableData();
  assert(in_data.values.size() == number_of_simd_values);
  assert(in_data.lambda_previous_id.size() == number_of_simd_values);
  assert(in_data.lambda_my_id.size() == number_of_simd_values);

  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = static_cast<std::int64_t>(communication_layer.GetMyId());
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  
  assert(output_owner_ >= 0);
  //The output owner is S_i
  if(uint64_t(output_owner_) == next_id || uint64_t(output_owner_) == kAll) {
    //We assume the role of S_i-1 here, sending lambda_i+1 to S_i
    auto payload = ToByteVector<T>(in_data.lambda_previous_id);
    auto message = 
      communication::BuildMessage(
        communication::MessageType::kSwiftOutputGate, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  auto output_hash_verifier = backend_.GetSwiftOutputHashVerifier();
  if(uint64_t(output_owner_) == previous_id || uint64_t(output_owner_) == kAll) {
    //We assume the role of S_i+1 here, preparing the hash of lambda_i+1, to be sent to S_i
    verifier_message_hash_data_.AssignData(in_data.lambda_my_id);
    output_hash_verifier->SetReady();
  }
  if (uint64_t(output_owner_) == my_id || uint64_t(output_owner_) == kAll) {
    //We assume the role of S_i here, receiving lambda_i+1 from S_i-1 and h_i+1 from S_i+1
    auto out_wire = std::dynamic_pointer_cast<swift::Wire<T>>(output_wires_[0]);
    assert(out_wire);
    auto& out_data = out_wire->GetMutableData();
    assert(out_data.values.size() == 0);
    assert(out_data.lambda_previous_id.size() == 0);
    assert(out_data.lambda_my_id.size() == 0);
    out_data.values.reserve(number_of_simd_values);
    auto const message = lambda_i_plus_1_future_.get(  );
    auto const payload = communication::GetMessage(message.data())->payload();
    auto lambda_i_plus_1 = FromByteVector<T>({payload->Data(), payload->size()});
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      //lambda_previous_id = lambda_i-1 and lambda_my_id = lambda_i
      out_data.values.emplace_back( 
        in_data.values[i] + in_data.lambda_previous_id[i] + in_data.lambda_my_id[i] + lambda_i_plus_1[i]);
    }
    assert(out_data.values.size() == number_of_simd_values);
    //We prepare to check lambda_i+1 with the hash we will receive from S_i+1
    verifier_check_hash_data_.AssignData(lambda_i_plus_1);
    output_hash_verifier->SetReady();
    output_hash_verifier->GetIsReadyCondition().Wait();
  }
}

template class OutputGate<std::uint8_t>;
template class OutputGate<std::uint16_t>;
template class OutputGate<std::uint32_t>;
template class OutputGate<std::uint64_t>;

template <typename T>
MultiplicationGate<T>::MultiplicationGate(swift::WirePointer<T> const& a,
                                          swift::WirePointer<T> const& b)
    : TwoGate(a->GetBackend()), 
      gamma_xy_my_id_(a->GetNumberOfSimdValues()),
      gamma_xy_previous_id_(a->GetNumberOfSimdValues()),
      triple_(backend_.GetSwiftVerifier()->ReserveTriples128(a->GetNumberOfSimdValues())) {
  using communication::MessageType::kSwiftSetupMultiplyGate;
  using communication::MessageType::kSwiftOnlineMultiplyGate;
  size_t number_of_simd_values = a->GetNumberOfSimdValues();
  assert(number_of_simd_values == b->GetNumberOfSimdValues());
  parent_a_ = {std::move(a)};
  parent_b_ = {std::move(b)};
  uint64_t my_id = GetCommunicationLayer().GetMyId();
  uint64_t previous_id = (my_id + 2) % 3;

  output_wires_ = 
    {GetRegister().template EmplaceWire<swift::Wire<T>>(
      backend_, number_of_simd_values, 
      std::vector<T>(number_of_simd_values),
      std::vector<T>(number_of_simd_values),
      std::vector<T>(number_of_simd_values))};

  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  multiply_future_setup_ =
    message_manager.RegisterReceive(previous_id, kSwiftSetupMultiplyGate, gate_id_);
    
  if(my_id == 0) {
    multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftOnlineMultiplyGate, gate_id_);
  } else if(my_id == 1) {
    multiply_future_online_ = 
      message_manager.RegisterReceive(2, kSwiftOnlineMultiplyGate, gate_id_);
  } else if(my_id == 2) {
    multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftOnlineMultiplyGate, gate_id_);
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    //We are S_0, so we reserve hash memory for the hash we will receive from S2
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        number_of_simd_values * sizeof(T), 2);
    //we also reserve memory for the hash we will be sending to S1 and S2
    verifier_s1_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        number_of_simd_values * sizeof(T), 1);
    verifier_s2_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        number_of_simd_values * sizeof(T), 2);
  } else {
    //We are S1 or S2 and thus will receive a hash from S0;
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        number_of_simd_values * sizeof(T), 0);
  }
  if(my_id == 2) {
    //We reserve memory for the hash we will be sending to S0
    verifier_s2_message_data_ = 
      multipy_hash_verifier->ReserveHashMessage(
        number_of_simd_values * sizeof(T), 0);
  }
}

template <typename T>
void MultiplicationGate<T>::EvaluateSetup() {
  using communication::MessageType::kSwiftSetupMultiplyGate;
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  auto out_wire = std::dynamic_pointer_cast<swift::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto& out_data = out_wire->GetMutableData();
  size_t number_of_simd_values = out_wire->GetNumberOfSimdValues();
  
  size_t const number_of_gamma_xy_bytes = number_of_simd_values * sizeof(UInt128);
  size_t const number_of_lambda_z_bytes = number_of_simd_values * sizeof(T);
  size_t const random_bytes = number_of_gamma_xy_bytes + number_of_lambda_z_bytes;
    
  //We assume the role of S_i and generate the random numbers we share with S_i+1
  auto& rng_i = backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
  //We assume the role of S_i+1 and generate the random numbers we share with S_i
  auto& rng_i_minus_1 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
  //randoms_my_id contains gamma_xy_my_id followed by lambda_z_my_id
  std::vector<uint8_t> randoms_my_id = 
    rng_i.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
  //randoms_previous_id contains gamma_xy_previous_id followed by lambda_z_previous_id
  std::vector<uint8_t> randoms_previous_id = 
    rng_i_minus_1.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
    
  {
    size_t lambda_z_offset = 0;
    uint8_t const* const lambda_z_my_id_pointer = 
      randoms_my_id.data() + number_of_gamma_xy_bytes;
    uint8_t const* const lambda_z_previous_id_pointer = 
      randoms_previous_id.data() + number_of_gamma_xy_bytes;
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      T lambda_z_my_id, lambda_z_previous_id;
      memcpy(&lambda_z_my_id, 
             lambda_z_my_id_pointer + lambda_z_offset, 
             sizeof(T));
      memcpy(&lambda_z_previous_id, 
             lambda_z_previous_id_pointer + lambda_z_offset, 
             sizeof(T));
      out_data.lambda_my_id[i] = lambda_z_my_id;
      out_data.lambda_previous_id[i] = lambda_z_previous_id;
      lambda_z_offset += sizeof(T);
    }
    assert(lambda_z_offset == number_of_lambda_z_bytes);
  }
  out_wire->SetSetupIsReady();
  

  auto a_wire = std::dynamic_pointer_cast<swift::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  assert(a_wire->GetNumberOfSimdValues() == number_of_simd_values);
  auto b_wire = std::dynamic_pointer_cast<swift::Wire<T>>(parent_b_[0]);
  assert(b_wire);
  assert(b_wire->GetNumberOfSimdValues() == number_of_simd_values);
  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();
  auto& a_data = a_wire->GetMutableData();
  auto& b_data = b_wire->GetMutableData();
  {
    size_t offset = 0;
    uint8_t const* const alpha_i_pointer = randoms_my_id.data();
    uint8_t const* const alpha_i_minus_1_pointer = randoms_previous_id.data();
    uint8_t* const c_i_pointer = randoms_my_id.data();
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      UInt128 alpha_i, alpha_i_minus_1;
      memcpy(&alpha_i, alpha_i_pointer + offset, sizeof(UInt128));
      memcpy(&alpha_i_minus_1, alpha_i_minus_1_pointer + offset, sizeof(UInt128));
      UInt128 c_i = 
        UInt128(a_data.lambda_my_id[i]) * UInt128(b_data.lambda_my_id[i]) +
        UInt128(a_data.lambda_my_id[i]) * UInt128(b_data.lambda_previous_id[i]) +
        UInt128(a_data.lambda_previous_id[i]) * UInt128(b_data.lambda_my_id[i]) +
        alpha_i - alpha_i_minus_1;
      memcpy(c_i_pointer + offset, &c_i, sizeof(UInt128));
      offset += sizeof(UInt128);
    }
    assert(offset == number_of_gamma_xy_bytes);
  }
  //Now the c_i values are in randoms_my_id[0,...,number_of_gamma_xy_bytes]
  
  {
    auto payload = std::span<uint8_t const>(randoms_my_id.data(), number_of_gamma_xy_bytes);
    auto message = communication::BuildMessage(kSwiftSetupMultiplyGate, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  
  {
    auto message = multiply_future_setup_.get();
    const auto payload = communication::GetMessage(message.data())->payload();
    auto received_data = std::span<uint8_t const>{payload->Data(), payload->size()};
    {
      size_t gamma_xy_offset = 0;
      uint8_t const* const gamma_xy_my_id_pointer = 
        randoms_my_id.data();
      uint8_t const* const gamma_xy_previous_id_pointer = 
        received_data.data();
      for(size_t i = 0; i != number_of_simd_values; ++i) {
        UInt128 gamma_xy_my_id, gamma_xy_previous_id;
        memcpy(&gamma_xy_my_id, 
               gamma_xy_my_id_pointer + gamma_xy_offset, 
               sizeof(UInt128));
        memcpy(&gamma_xy_previous_id, 
               gamma_xy_previous_id_pointer + gamma_xy_offset,
               sizeof(UInt128));
        triple_.AppendTriple(
          UInt128(a_data.lambda_my_id[i]), UInt128(a_data.lambda_previous_id[i]),
          UInt128(b_data.lambda_my_id[i]), UInt128(b_data.lambda_previous_id[i]),
          gamma_xy_my_id, gamma_xy_previous_id);
        gamma_xy_my_id_[i] = T(gamma_xy_my_id);
        gamma_xy_previous_id_[i] = T(gamma_xy_previous_id);
        gamma_xy_offset += sizeof(UInt128);
      }
      backend_.GetSwiftVerifier()->SetReady();
      assert(gamma_xy_offset == number_of_gamma_xy_bytes);
    }
  }
}

template <typename T>
void MultiplicationGate<T>::EvaluateOnline() {
  using communication::MessageType::kSwiftOnlineMultiplyGate;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<swift::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<swift::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<swift::Wire<T>>(parent_b_[0]);
  assert(b_wire);
  size_t number_of_simd_values = a_wire->GetNumberOfSimdValues();
  assert(b_wire->GetNumberOfSimdValues() == number_of_simd_values);
  assert(out_wire->GetNumberOfSimdValues() == number_of_simd_values);
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
  
  auto& a_data = a_wire->GetMutableData();
  auto& b_data = b_wire->GetMutableData();
  auto& out_data = out_wire->GetMutableData();
  
  std::vector<T> m_my_id, m_previous_id;
  m_my_id.reserve(number_of_simd_values);
  m_previous_id.reserve(number_of_simd_values);
  
  for(size_t i = 0; i != number_of_simd_values; ++i) {
    m_my_id.emplace_back(
      a_data.values[i] * b_data.lambda_my_id[i]
      + b_data.values[i] * a_data.lambda_my_id[i]
      + gamma_xy_my_id_[i] - out_data.lambda_my_id[i]);
    m_previous_id.emplace_back( 
      a_data.values[i] * b_data.lambda_previous_id[i]
      + b_data.values[i] * a_data.lambda_previous_id[i]
      + gamma_xy_previous_id_[i] - out_data.lambda_previous_id[i]);
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    verifier_s1_message_data_.AssignData(m_previous_id);
    multipy_hash_verifier->SetReady();
    verifier_s2_message_data_.AssignData(m_my_id);
    multipy_hash_verifier->SetReady();
  }
  else if(my_id == 1) {
    //We are S1 so we send m_0 to S2, which is m_previous_id
    //and m_1 to S0, which is m_my_id
    {
      auto payload = ToByteVector<T>(m_previous_id);
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
    }
    
    {
      auto payload = ToByteVector<T>(m_my_id);
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(0, message.Release());
    }
  } else if(my_id == 2) {
    //We are S2 so we send m_2 to S1, which is m_my_id
    //and H(m_1) which is H(m_previous_id)
    {
      auto payload = ToByteVector<T>(m_my_id);
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(1, message.Release());
    }
    verifier_s2_message_data_.AssignData(m_previous_id);
    multipy_hash_verifier->SetReady();
  } else {
    assert(false);
  }
  
  {
    auto message = multiply_future_online_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    auto m_missing_id = FromByteVector<T>({payload->Data(), payload->size()});
    verifier_received_hash_data_.AssignData(m_missing_id);
    multipy_hash_verifier->SetReady();
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      out_data.values[i] = 
        m_previous_id[i] + m_my_id[i] + m_missing_id[i] 
        + a_data.values[i] * b_data.values[i];
    }
  }
}

template class MultiplicationGate<std::uint8_t>;
template class MultiplicationGate<std::uint16_t>;
template class MultiplicationGate<std::uint32_t>;
template class MultiplicationGate<std::uint64_t>;

template <typename T>
SociumMultiplicationGate<T>::SociumMultiplicationGate(swift::WirePointer<T> const& a,
                                          swift::WirePointer<T> const& b)
    : TwoGate(a->GetBackend()), 
      gamma_xy_my_id_(a->GetNumberOfSimdValues()),
      gamma_xy_previous_id_(a->GetNumberOfSimdValues()),
      triple_(backend_.GetSociumVerifier()->ReserveTriples128(a->GetNumberOfSimdValues())) {
  using communication::MessageType::kSociumSetupMultiplyGate;
  using communication::MessageType::kSociumOnlineMultiplyGate;
  size_t number_of_simd_values = a->GetNumberOfSimdValues();
  assert(number_of_simd_values == b->GetNumberOfSimdValues());
  parent_a_ = {std::move(a)};
  parent_b_ = {std::move(b)};
  uint64_t my_id = GetCommunicationLayer().GetMyId();
  uint64_t previous_id = (my_id + 2) % 3;

  output_wires_ = 
    {GetRegister().template EmplaceWire<swift::Wire<T>>(
      backend_, number_of_simd_values, 
      std::vector<T>(number_of_simd_values),
      std::vector<T>(number_of_simd_values),
      std::vector<T>(number_of_simd_values))};

  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  if (my_id == 0 || my_id == 1) {
    multiply_future_setup_ =
      message_manager.RegisterReceive(previous_id, kSociumSetupMultiplyGate, gate_id_);
  }
    
  if(my_id == 0) {
    multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSociumOnlineMultiplyGate, gate_id_);
  } else if(my_id == 1) {
    multiply_future_online_ = 
      message_manager.RegisterReceive(2, kSociumOnlineMultiplyGate, gate_id_);
  } else if(my_id == 2) {
    multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSociumOnlineMultiplyGate, gate_id_);
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    //We are S_0, so we reserve memory for the hash we will be sending to S1
    verifier_s1_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        number_of_simd_values * sizeof(T), 1);
  } else if (my_id == 1) {
    //We are S1 and thus will receive a hash from S0;
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(number_of_simd_values * sizeof(T), 0);
  }
}

template <typename T>
void SociumMultiplicationGate<T>::EvaluateSetup() {
  using communication::MessageType::kSociumSetupMultiplyGate;
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  auto out_wire = std::dynamic_pointer_cast<swift::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto& out_data = out_wire->GetMutableData();
  size_t number_of_simd_values = out_wire->GetNumberOfSimdValues();
  
  size_t const number_of_gamma_xy_bytes = number_of_simd_values * sizeof(UInt128);
  size_t const number_of_lambda_z_bytes = number_of_simd_values * sizeof(T);
  size_t const random_bytes = number_of_gamma_xy_bytes + number_of_lambda_z_bytes;

    
  //We assume the role of S_i and generate the random numbers we share with S_i+1
  auto& rng_i = backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
  //We assume the role of S_i+1 and generate the random numbers we share with S_i
  auto& rng_i_minus_1 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
  //randoms_my_id contains gamma_xy_my_id followed by lambda_z_my_id
  std::vector<uint8_t> randoms_my_id = 
    rng_i.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
  //randoms_previous_id contains gamma_xy_previous_id followed by lambda_z_previous_id
  std::vector<uint8_t> randoms_previous_id = 
    rng_i_minus_1.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
    
  {
    size_t lambda_z_offset = 0;
    uint8_t const* const lambda_z_my_id_pointer = 
      randoms_my_id.data() + number_of_gamma_xy_bytes;
    uint8_t const* const lambda_z_previous_id_pointer = 
      randoms_previous_id.data() + number_of_gamma_xy_bytes;
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      T lambda_z_my_id, lambda_z_previous_id;
      memcpy(&lambda_z_my_id, 
             lambda_z_my_id_pointer + lambda_z_offset, 
             sizeof(T));
      memcpy(&lambda_z_previous_id, 
             lambda_z_previous_id_pointer + lambda_z_offset, 
             sizeof(T));
      out_data.lambda_my_id[i] = lambda_z_my_id;
      out_data.lambda_previous_id[i] = lambda_z_previous_id;
      lambda_z_offset += sizeof(T);
    }
    assert(lambda_z_offset == number_of_lambda_z_bytes);
  }
  out_wire->SetSetupIsReady();
  
  auto a_wire = std::dynamic_pointer_cast<swift::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  assert(a_wire->GetNumberOfSimdValues() == number_of_simd_values);
  auto b_wire = std::dynamic_pointer_cast<swift::Wire<T>>(parent_b_[0]);
  assert(b_wire);
  assert(b_wire->GetNumberOfSimdValues() == number_of_simd_values);
  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();
  auto& a_data = a_wire->GetMutableData();
  auto& b_data = b_wire->GetMutableData();
  {
    size_t offset = 0;
    uint8_t const* const alpha_i_pointer = randoms_my_id.data();
    uint8_t const* const alpha_i_minus_1_pointer = randoms_previous_id.data();
    uint8_t* const c_i_pointer = randoms_my_id.data();
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      UInt128 alpha_i, alpha_i_minus_1;
      memcpy(&alpha_i, alpha_i_pointer + offset, sizeof(UInt128));
      memcpy(&alpha_i_minus_1, alpha_i_minus_1_pointer + offset, sizeof(UInt128));
      UInt128 c_i = 
        UInt128(a_data.lambda_my_id[i]) * UInt128(b_data.lambda_my_id[i]) +
        UInt128(a_data.lambda_my_id[i]) * UInt128(b_data.lambda_previous_id[i]) +
        UInt128(a_data.lambda_previous_id[i]) * UInt128(b_data.lambda_my_id[i]) +
        alpha_i - alpha_i_minus_1;
      memcpy(c_i_pointer + offset, &c_i, sizeof(UInt128));
      offset += sizeof(UInt128);
    }
    assert(offset == number_of_gamma_xy_bytes);
  }
  //Now the c_i values are in randoms_my_id[0,...,number_of_gamma_xy_bytes]
  
  if (my_id == 0 || my_id == 2) { // S1 does not send in Socium
    auto payload = std::span<uint8_t const>(randoms_my_id.data(), number_of_gamma_xy_bytes);
    auto message = communication::BuildMessage(kSociumSetupMultiplyGate, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  
  if (my_id == 0 || my_id == 1) { // S2 does not receive in Socium
    auto message = multiply_future_setup_.get();
    const auto payload = communication::GetMessage(message.data())->payload();
    auto received_data = std::span<uint8_t const>{payload->Data(), payload->size()};
    {
      size_t gamma_xy_offset = 0;
      uint8_t const* const gamma_xy_my_id_pointer = 
        randoms_my_id.data();
      uint8_t const* const gamma_xy_previous_id_pointer = 
        received_data.data();
      for(size_t i = 0; i != number_of_simd_values; ++i) {
        UInt128 gamma_xy_my_id, gamma_xy_previous_id;
        memcpy(&gamma_xy_my_id, 
               gamma_xy_my_id_pointer + gamma_xy_offset, 
               sizeof(UInt128));
        memcpy(&gamma_xy_previous_id, 
               gamma_xy_previous_id_pointer + gamma_xy_offset,
               sizeof(UInt128));
        triple_.AppendTriple(UInt128(a_data.lambda_my_id[i]), UInt128(a_data.lambda_previous_id[i]),
                             UInt128(b_data.lambda_my_id[i]), UInt128(b_data.lambda_previous_id[i]),
                             gamma_xy_my_id, gamma_xy_previous_id);
        gamma_xy_my_id_[i] = T(gamma_xy_my_id);
        gamma_xy_previous_id_[i] = T(gamma_xy_previous_id);
        gamma_xy_offset += sizeof(UInt128);
      }
      backend_.GetSociumVerifier()->SetReady();
      assert(gamma_xy_offset == number_of_gamma_xy_bytes);
    }
  } else { // S2
    UInt128 empty = 0;
    size_t gamma_xy_offset = 0;
    uint8_t const* const gamma_xy_my_id_pointer = randoms_my_id.data();
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      UInt128 gamma_xy_my_id;
      memcpy(&gamma_xy_my_id, gamma_xy_my_id_pointer + gamma_xy_offset, sizeof(UInt128));

      triple_.AppendTriple(UInt128(a_data.lambda_my_id[i]), UInt128(a_data.lambda_previous_id[i]),
                           UInt128(b_data.lambda_my_id[i]), UInt128(b_data.lambda_previous_id[i]),
                           gamma_xy_my_id, empty);
      gamma_xy_my_id_[i]= T(gamma_xy_my_id);
      gamma_xy_offset += sizeof(UInt128);
    }
    backend_.GetSociumVerifier()->SetReady();

    assert(gamma_xy_offset == number_of_gamma_xy_bytes);
  }
}

template <typename T>
void SociumMultiplicationGate<T>::EvaluateOnline() {
  using communication::MessageType::kSociumOnlineMultiplyGate;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<swift::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<swift::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<swift::Wire<T>>(parent_b_[0]);
  assert(b_wire);
  size_t number_of_simd_values = a_wire->GetNumberOfSimdValues();
  assert(b_wire->GetNumberOfSimdValues() == number_of_simd_values);
  assert(out_wire->GetNumberOfSimdValues() == number_of_simd_values);
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
  
  auto& a_data = a_wire->GetMutableData();
  auto& b_data = b_wire->GetMutableData();
  auto& out_data = out_wire->GetMutableData();
  
  std::vector<T> m_my_id, m_previous_id;
  m_my_id.reserve(number_of_simd_values);
  if (my_id != 2) {
    m_previous_id.reserve(number_of_simd_values); // For S1, this will be Y0+Y1
  }
  
  for(size_t i = 0; i != number_of_simd_values; ++i) {
    m_my_id.emplace_back(
      a_data.values[i] * b_data.lambda_my_id[i]
      + b_data.values[i] * a_data.lambda_my_id[i]
      + gamma_xy_my_id_[i] - out_data.lambda_my_id[i]);
    if (my_id != 2) {
      m_previous_id.emplace_back( 
        a_data.values[i] * b_data.lambda_previous_id[i]
        + b_data.values[i] * a_data.lambda_previous_id[i]
        + gamma_xy_previous_id_[i] - out_data.lambda_previous_id[i]);
    }
    if (my_id == 1) {
      m_previous_id[i] += m_my_id[i];
    }
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    verifier_s1_message_data_.AssignData(m_previous_id);
    multipy_hash_verifier->SetReady();
  }
  else if(my_id == 1) {
    //We are S1 so we send m_0+m_1 to S2, which is m_previous_id
    //and m_0+m_1 to S0, which is m_previous_id
    {
      auto payload = ToByteVector<T>(m_previous_id);
      auto message = 
        communication::BuildMessage(kSociumOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
    }
    
    {
      auto payload = ToByteVector<T>(m_previous_id);
      auto message = 
        communication::BuildMessage(kSociumOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(0, message.Release());
    }
  } else if(my_id == 2) {
    //We are S2 so we send m_2 to S1, which is m_my_id
    {
      auto payload = ToByteVector<T>(m_my_id);
      auto message = 
        communication::BuildMessage(kSociumOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(1, message.Release());
    }
  } else {
    assert(false);
  }
  
  {
    auto message = multiply_future_online_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    auto m_missing_id = FromByteVector<T>({payload->Data(), payload->size()});
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      if (my_id == 0) { // Got m0+m1, have m2
        out_data.values[i] = m_missing_id[i] + m_previous_id[i] + a_data.values[i] * b_data.values[i];
      } else if (my_id == 1) { // Got m2, have m0+m1 (in prev)
        out_data.values[i] = m_missing_id[i] + m_previous_id[i] + a_data.values[i] * b_data.values[i];
      } else if (my_id == 2) { // Got m0+m1, have m2
        out_data.values[i] = m_missing_id[i] + m_my_id[i] + a_data.values[i] * b_data.values[i];
      } else {
        assert(false);
      }
    }
    if (my_id == 1) {
      verifier_received_hash_data_.AssignData(m_missing_id);
      multipy_hash_verifier->SetReady();
    }
  }
}

template class SociumMultiplicationGate<std::uint8_t>;
template class SociumMultiplicationGate<std::uint16_t>;
template class SociumMultiplicationGate<std::uint32_t>;
template class SociumMultiplicationGate<std::uint64_t>;

template<typename T>
AdditionGate<T>::AdditionGate(swift::WirePointer<T> const& a, 
                              swift::WirePointer<T> const& b)
    : TwoGate(a->GetBackend()) {
  size_t number_of_simd_values = a->GetNumberOfSimdValues();
  assert(number_of_simd_values == b->GetNumberOfSimdValues());
  parent_a_ = {std::move(a)};
  parent_b_ = {std::move(b)};

  output_wires_ = 
    {GetRegister().template EmplaceWire<swift::Wire<T>>(
      backend_, number_of_simd_values,
      std::vector<T>(number_of_simd_values),
      std::vector<T>(number_of_simd_values),
      std::vector<T>(number_of_simd_values))};
}

template<typename T>
void AdditionGate<T>::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<swift::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<swift::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<swift::Wire<T>>(parent_b_[0]);
  assert(b_wire);
  
  size_t number_of_simd_values = parent_a_[0]->GetNumberOfSimdValues();

  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();
  
  auto const& a_data = a_wire->GetData();
  auto const& b_data = b_wire->GetData();
  auto& out_data = out_wire->GetMutableData();
  
  for(size_t i = 0; i != number_of_simd_values; ++i) {
    out_data.lambda_my_id[i] = a_data.lambda_my_id[i] + b_data.lambda_my_id[i];
    out_data.lambda_previous_id[i] = a_data.lambda_previous_id[i] + b_data.lambda_previous_id[i];
  }
  
  out_wire->SetSetupIsReady();
}

template<typename T>
void AdditionGate<T>::EvaluateOnline() {
  auto out_wire = std::dynamic_pointer_cast<swift::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<swift::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<swift::Wire<T>>(parent_b_[0]);
  assert(b_wire);
  WaitSetup();
  assert(setup_is_ready_);
  
  size_t number_of_simd_values = parent_a_[0]->GetNumberOfSimdValues();
  
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
  
  auto const& a_data = a_wire->GetData();
  auto const& b_data = b_wire->GetData();
  auto& out_data = out_wire->GetMutableData();
  
  for(size_t i = 0; i != number_of_simd_values; ++i) {
    out_data.values[i] = a_data.values[i] + b_data.values[i];
  }
}

template class AdditionGate<std::uint8_t>;
template class AdditionGate<std::uint16_t>;
template class AdditionGate<std::uint32_t>;
template class AdditionGate<std::uint64_t>;

constexpr size_t BitsToBytes(size_t bits) {
  return (bits + CHAR_BIT - 1)/CHAR_BIT;
}

AndGate::AndGate(swift::BooleanWirePointer const& a, swift::BooleanWirePointer const& b)
    : TwoGate(a->GetBackend()), 
      gamma_xy_my_id_(a->GetNumberOfSimdValues()),
      gamma_xy_previous_id_(a->GetNumberOfSimdValues()),
      triple_(backend_.GetSwiftVerifier()->ReserveTriples64(a->GetNumberOfSimdValues())) {
  using communication::MessageType::kSwiftSetupMultiplyGate;
  using communication::MessageType::kSwiftOnlineMultiplyGate;
  size_t number_of_simd_values = a->GetNumberOfSimdValues();
  assert(number_of_simd_values == b->GetNumberOfSimdValues());
  parent_a_ = {std::move(a)};
  parent_b_ = {std::move(b)};
  uint64_t my_id = GetCommunicationLayer().GetMyId();
  uint64_t previous_id = (my_id + 2) % 3;

  output_wires_ = 
    {GetRegister().template EmplaceWire<swift::BooleanWire>(
      backend_,
      BitVector<>(number_of_simd_values, false),
      BitVector<>(number_of_simd_values, false),
      BitVector<>(number_of_simd_values, false))};
  gamma_xy_my_id_ = BitVector<>(number_of_simd_values, false);
  gamma_xy_previous_id_ = BitVector<>(number_of_simd_values, false);

  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  multiply_future_setup_ =
    message_manager.RegisterReceive(previous_id, kSwiftSetupMultiplyGate, gate_id_);
    
  if(my_id == 0) {
    multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftOnlineMultiplyGate, gate_id_);
  } else if(my_id == 1) {
    multiply_future_online_ = 
      message_manager.RegisterReceive(2, kSwiftOnlineMultiplyGate, gate_id_);
  } else if(my_id == 2) {
    multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftOnlineMultiplyGate, gate_id_);
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    //We are S_0, so we reserve hash memory for the hash we will receive from S2
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        BitsToBytes(number_of_simd_values), 2);
    //we also reserve memory for the hash we will be sending to S1 and S2
    verifier_s1_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        BitsToBytes(number_of_simd_values), 1);
    verifier_s2_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        BitsToBytes(number_of_simd_values), 2);
  } else {
    //We are S1 or S2 and thus will receive a hash from S0;
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        BitsToBytes(number_of_simd_values), 0);
  }
  
  if(my_id == 2) {
    //We reserve memory for the hash we will be sending to S0
    verifier_s2_message_data_ = 
      multipy_hash_verifier->ReserveHashMessage(
        number_of_simd_values, 0);
  }
}

void AndGate::EvaluateSetup() {
  using communication::MessageType::kSwiftSetupMultiplyGate;
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  auto out_wire = std::dynamic_pointer_cast<swift::BooleanWire>(output_wires_[0]);
  assert(out_wire);
  auto& out_lambdas_my_id = out_wire->GetMutableLambdasMyId();
  auto& out_lambdas_previous_id = out_wire->GetMutableLambdasPreviousId();
  size_t const number_of_simd_values = out_wire->GetNumberOfSimdValues();
  
  size_t const number_of_gamma_xy_bytes = number_of_simd_values * sizeof(uint64_t);
  size_t const number_of_lambda_z_bytes = BitsToBytes(number_of_simd_values);
  size_t const random_bytes = number_of_gamma_xy_bytes + number_of_lambda_z_bytes;

  //We assume the role of S_i and generate the random numbers we share with S_i+1
  auto& rng_i = backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
  //We assume the role of S_i+1 and generate the random numbers we share with S_i
  auto& rng_i_minus_1 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
  //randoms_my_id contains gamma_xy_my_id followed by lambda_z_my_id
  std::vector<uint8_t> randoms_my_id = 
    rng_i.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
  //randoms_previous_id contains gamma_xy_previous_id followed by lambda_z_previous_id
  std::vector<uint8_t> randoms_previous_id = 
    rng_i_minus_1.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
    
  {
    size_t lambda_z_offset = 0;
    uint8_t const* const lambda_z_my_id_pointer = 
      randoms_my_id.data() + number_of_gamma_xy_bytes;
    uint8_t const* const lambda_z_previous_id_pointer = 
      randoms_previous_id.data() + number_of_gamma_xy_bytes;
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      bool lambda_z_my_id = 
        (lambda_z_my_id_pointer[lambda_z_offset/CHAR_BIT] >> (lambda_z_offset % CHAR_BIT)) & 0x1;
      bool lambda_z_previous_id = 
        (lambda_z_previous_id_pointer[lambda_z_offset/CHAR_BIT] >> (lambda_z_offset % CHAR_BIT)) & 0x1;
      out_lambdas_my_id.Set(lambda_z_my_id, i);
      out_lambdas_previous_id.Set(lambda_z_previous_id, i);
      lambda_z_offset += 1;
    }
    assert(BitsToBytes(lambda_z_offset) == number_of_lambda_z_bytes);
  }
  out_wire->SetSetupIsReady();
  
  auto a_wire = std::dynamic_pointer_cast<swift::BooleanWire>(parent_a_[0]);
  assert(a_wire);
  assert(a_wire->GetNumberOfSimdValues() == number_of_simd_values);
  auto b_wire = std::dynamic_pointer_cast<swift::BooleanWire>(parent_b_[0]);
  assert(b_wire);
  assert(b_wire->GetNumberOfSimdValues() == number_of_simd_values);
  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();
  auto const& a_lambdas_my_id = a_wire->GetLambdasMyId();
  auto const& a_lambdas_previous_id = a_wire->GetLambdasPreviousId();
  auto const& b_lambdas_my_id = b_wire->GetLambdasMyId();
  auto const& b_lambdas_previous_id = b_wire->GetLambdasPreviousId();
  {
    size_t offset = 0;
    uint8_t const* const alpha_i_pointer = randoms_my_id.data();
    uint8_t const* const alpha_i_minus_1_pointer = randoms_previous_id.data();
    uint8_t* const c_i_pointer = randoms_my_id.data();
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      uint64_t alpha_i, alpha_i_minus_1;
      memcpy(&alpha_i, alpha_i_pointer + offset, sizeof(uint64_t));
      memcpy(&alpha_i_minus_1, alpha_i_minus_1_pointer + offset, sizeof(uint64_t));
      uint64_t c_i = 
        uint64_t(a_lambdas_my_id.Get(i)) * uint64_t(b_lambdas_my_id.Get(i)) +
        uint64_t(a_lambdas_my_id.Get(i)) * uint64_t(b_lambdas_previous_id.Get(i)) +
        uint64_t(a_lambdas_previous_id.Get(i)) * uint64_t(b_lambdas_my_id.Get(i)) +
        alpha_i - alpha_i_minus_1;
      memcpy(c_i_pointer + offset, &c_i, sizeof(uint64_t));
      offset += sizeof(uint64_t);
    }
    assert(offset == number_of_gamma_xy_bytes);
  }
  //Now the c_i values are in randoms_my_id[0,...,number_of_gamma_xy_bytes]
  
  {
    auto payload = std::span<uint8_t const>(randoms_my_id.data(), number_of_gamma_xy_bytes);
    auto message = communication::BuildMessage(kSwiftSetupMultiplyGate, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  
  {
    auto message = multiply_future_setup_.get();
    const auto payload = communication::GetMessage(message.data())->payload();
    auto received_data = std::span<uint8_t const>{payload->Data(), payload->size()};
    {
      size_t gamma_xy_offset = 0;
      uint8_t const* const gamma_xy_my_id_pointer = 
        randoms_my_id.data();
      uint8_t const* const gamma_xy_previous_id_pointer = 
        received_data.data();
      for(size_t i = 0; i != number_of_simd_values; ++i) {
        uint64_t gamma_xy_my_id, gamma_xy_previous_id;
        memcpy(&gamma_xy_my_id, 
               gamma_xy_my_id_pointer + gamma_xy_offset, 
               sizeof(uint64_t));
        memcpy(&gamma_xy_previous_id, 
               gamma_xy_previous_id_pointer + gamma_xy_offset,
               sizeof(uint64_t));
        triple_.AppendTriple(uint64_t(a_lambdas_my_id.Get(i)), uint64_t(a_lambdas_previous_id.Get(i)),
                             uint64_t(b_lambdas_my_id.Get(i)), uint64_t(b_lambdas_previous_id.Get(i)),
                             gamma_xy_my_id, gamma_xy_previous_id);
        gamma_xy_my_id_.Set(gamma_xy_my_id & 0x1, i);
        gamma_xy_previous_id_.Set(gamma_xy_previous_id & 0x1, i);
        gamma_xy_offset += sizeof(uint64_t);
      }
      backend_.GetSwiftVerifier()->SetReady();
      assert(gamma_xy_offset == number_of_gamma_xy_bytes);
    }
  }
}

void AndGate::EvaluateOnline() {
  using communication::MessageType::kSwiftOnlineMultiplyGate;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<swift::BooleanWire>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<swift::BooleanWire>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<swift::BooleanWire>(parent_b_[0]);
  assert(b_wire);
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
  
  auto const& a_lambdas_my_id = a_wire->GetLambdasMyId();
  auto const& a_lambdas_previous_id = a_wire->GetLambdasPreviousId();
  auto const& a_values = a_wire->GetValues();
  auto const& b_lambdas_my_id = b_wire->GetLambdasMyId();
  auto const& b_lambdas_previous_id = b_wire->GetLambdasPreviousId();
  auto const& b_values = a_wire->GetValues();
  auto& out_lambdas_my_id = out_wire->GetMutableLambdasMyId();
  auto& out_lambdas_previous_id = out_wire->GetMutableLambdasPreviousId();
  auto& out_values = out_wire->GetMutableValues();
  
  BitVector<> m_my_id = 
    (a_values & b_lambdas_my_id) ^ (b_values & a_lambdas_my_id)
    ^ gamma_xy_my_id_ ^ out_lambdas_my_id; 
  BitVector<> m_previous_id = 
    (a_values & b_lambdas_previous_id) ^ (b_values & a_lambdas_previous_id)
    ^ gamma_xy_previous_id_ ^ out_lambdas_previous_id;
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    verifier_s1_message_data_.AssignData(m_previous_id.GetData());
    multipy_hash_verifier->SetReady();
    verifier_s2_message_data_.AssignData(m_my_id.GetData());
    multipy_hash_verifier->SetReady();
  }
  else if(my_id == 1) {
    //We are S1 so we send m_0 to S2, which is m_previous_id
    //and m_1 to S0, which is m_my_id
    {
      std::span<uint8_t const> payload(
        reinterpret_cast<uint8_t const*>(m_previous_id.GetData().data()), 
        m_previous_id.GetData().size());
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
    }
    
    {
      std::span<uint8_t const> payload(
        reinterpret_cast<uint8_t const*>(m_my_id.GetData().data()), 
        m_my_id.GetData().size());
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(0, message.Release());
    }
  } else if(my_id == 2) {
    //We are S2 so we send m_2 to S1, which is m_my_id
    //and H(m_1) which is H(m_previous_id)
    {
      std::span<uint8_t const> payload(
        reinterpret_cast<uint8_t const*>(m_my_id.GetData().data()), 
        m_my_id.GetData().size());
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(1, message.Release());
    }
    verifier_s2_message_data_.AssignData(m_previous_id.GetData());
    multipy_hash_verifier->SetReady();
  } else {
    assert(false);
  }
  
  {
    auto message = multiply_future_online_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    BitVector<> m_missing_id(payload->Data(), payload->size());
    verifier_received_hash_data_.AssignData(m_missing_id.GetData());
    multipy_hash_verifier->SetReady();
    out_values = m_previous_id ^ m_my_id ^ m_missing_id ^ (a_values & b_values);
  }
}

SociumAndGate::SociumAndGate(swift::BooleanWirePointer const& a, swift::BooleanWirePointer const& b)
    : TwoGate(a->GetBackend()), 
      gamma_xy_my_id_(a->GetNumberOfSimdValues()),
      gamma_xy_previous_id_(a->GetNumberOfSimdValues()),
      triple_(backend_.GetSociumVerifier()->ReserveTriples64(a->GetNumberOfSimdValues())) {
  using communication::MessageType::kSociumSetupMultiplyGate;
  using communication::MessageType::kSociumOnlineMultiplyGate;
  size_t number_of_simd_values = a->GetNumberOfSimdValues();
  assert(number_of_simd_values == b->GetNumberOfSimdValues());
  parent_a_ = {std::move(a)};
  parent_b_ = {std::move(b)};
  uint64_t my_id = GetCommunicationLayer().GetMyId();
  uint64_t previous_id = (my_id + 2) % 3;

  output_wires_ = 
    {GetRegister().template EmplaceWire<swift::BooleanWire>(
      backend_,
      BitVector<>(number_of_simd_values, false),
      BitVector<>(number_of_simd_values, false),
      BitVector<>(number_of_simd_values, false))};
  gamma_xy_my_id_ = BitVector<>(number_of_simd_values, false);
  gamma_xy_previous_id_ = BitVector<>(number_of_simd_values, false);

  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  if (my_id == 0 || my_id == 1) { // S2 does not receive in setup
    multiply_future_setup_ =
      message_manager.RegisterReceive(previous_id, kSociumSetupMultiplyGate, gate_id_);
  }
    
  if(my_id == 0) {
    multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSociumOnlineMultiplyGate, gate_id_);
  } else if(my_id == 1) {
    multiply_future_online_ = 
      message_manager.RegisterReceive(2, kSociumOnlineMultiplyGate, gate_id_);
  } else if(my_id == 2) {
    multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSociumOnlineMultiplyGate, gate_id_);
  } else {
    assert(false);
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    //We are S_0, so we reserve memory for the hash we will be sending to S1
    verifier_s1_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        BitsToBytes(number_of_simd_values), 1);
  } else if (my_id == 1) {
    //We are S1 and thus will receive a hash from S0;
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        BitsToBytes(number_of_simd_values), 0);
  }
}

void SociumAndGate::EvaluateSetup() {
  using communication::MessageType::kSociumSetupMultiplyGate;
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  auto out_wire = std::dynamic_pointer_cast<swift::BooleanWire>(output_wires_[0]);
  assert(out_wire);
  size_t number_of_simd_values = out_wire->GetNumberOfSimdValues();
  auto& out_lambdas_my_id = out_wire->GetMutableLambdasMyId();
  auto& out_lambdas_previous_id = out_wire->GetMutableLambdasPreviousId();
  
  size_t const number_of_gamma_xy_bytes = number_of_simd_values * sizeof(uint64_t);
  size_t const number_of_lambda_z_bytes = BitsToBytes(number_of_simd_values);
  size_t const random_bytes = number_of_gamma_xy_bytes + number_of_lambda_z_bytes;

  //We assume the role of S_i and generate the random numbers we share with S_i+1
  auto& rng_i = backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
  //We assume the role of S_i+1 and generate the random numbers we share with S_i
  auto& rng_i_minus_1 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
  //randoms_my_id contains gamma_xy_my_id followed by lambda_z_my_id
  std::vector<uint8_t> randoms_my_id = 
    rng_i.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
  //randoms_previous_id contains gamma_xy_previous_id followed by lambda_z_previous_id
  std::vector<uint8_t> randoms_previous_id = 
    rng_i_minus_1.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
    
  {
    size_t lambda_z_offset = 0;
    uint8_t const* const lambda_z_my_id_pointer = 
      randoms_my_id.data() + number_of_gamma_xy_bytes;
    uint8_t const* const lambda_z_previous_id_pointer = 
      randoms_previous_id.data() + number_of_gamma_xy_bytes;
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      bool lambda_z_my_id = 
        (lambda_z_my_id_pointer[lambda_z_offset/CHAR_BIT] >> (lambda_z_offset % CHAR_BIT)) & 0x1;
      bool lambda_z_previous_id = 
        (lambda_z_previous_id_pointer[lambda_z_offset/CHAR_BIT] >> (lambda_z_offset % CHAR_BIT)) & 0x1;
      out_lambdas_my_id.Set(lambda_z_my_id, i);
      out_lambdas_previous_id.Set(lambda_z_previous_id, i);
      lambda_z_offset += 1;
    }
    assert(BitsToBytes(lambda_z_offset) == number_of_lambda_z_bytes);
  }
  out_wire->SetSetupIsReady();
  
  auto a_wire = std::dynamic_pointer_cast<swift::BooleanWire>(parent_a_[0]);
  assert(a_wire);
  assert(a_wire->GetNumberOfSimdValues() == number_of_simd_values);
  auto b_wire = std::dynamic_pointer_cast<swift::BooleanWire>(parent_b_[0]);
  assert(b_wire);
  assert(b_wire->GetNumberOfSimdValues() == number_of_simd_values);
  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();
  auto const& a_lambdas_my_id = a_wire->GetLambdasMyId();
  auto const& a_lambdas_previous_id = a_wire->GetLambdasPreviousId();
  auto const& b_lambdas_my_id = b_wire->GetLambdasMyId();
  auto const& b_lambdas_previous_id = b_wire->GetLambdasPreviousId();
  {
    size_t offset = 0;
    uint8_t const* const alpha_i_pointer = randoms_my_id.data();
    uint8_t const* const alpha_i_minus_1_pointer = randoms_previous_id.data();
    uint8_t* const c_i_pointer = randoms_my_id.data();
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      uint64_t alpha_i, alpha_i_minus_1;
      memcpy(&alpha_i, alpha_i_pointer + offset, sizeof(uint64_t));
      memcpy(&alpha_i_minus_1, alpha_i_minus_1_pointer + offset, sizeof(uint64_t));
      uint64_t c_i = 
        uint64_t(a_lambdas_my_id.Get(i)) * uint64_t(b_lambdas_my_id.Get(i)) +
        uint64_t(a_lambdas_my_id.Get(i)) * uint64_t(b_lambdas_previous_id.Get(i)) +
        uint64_t(a_lambdas_previous_id.Get(i)) * uint64_t(b_lambdas_my_id.Get(i)) +
        alpha_i - alpha_i_minus_1;
      memcpy(c_i_pointer + offset, &c_i, sizeof(uint64_t));
      offset += sizeof(uint64_t);
    }
    assert(offset == number_of_gamma_xy_bytes);
  }
  //Now the c_i values are in randoms_my_id[0,...,number_of_gamma_xy_bytes]
  
  if (my_id == 0 || my_id == 2) { // S1 does not send
    auto payload = std::span<uint8_t const>(randoms_my_id.data(), number_of_gamma_xy_bytes);
    auto message = communication::BuildMessage(kSociumSetupMultiplyGate, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  
  if (my_id == 0 || my_id == 1) { // S2 does not receive
    auto message = multiply_future_setup_.get();
    const auto payload = communication::GetMessage(message.data())->payload();
    auto received_data = std::span<uint8_t const>{payload->Data(), payload->size()};
    {
      size_t gamma_xy_offset = 0;
      uint8_t const* const gamma_xy_my_id_pointer = 
        randoms_my_id.data();
      uint8_t const* const gamma_xy_previous_id_pointer = 
        received_data.data();
      for(size_t i = 0; i != number_of_simd_values; ++i) {
        uint64_t gamma_xy_my_id, gamma_xy_previous_id;
        memcpy(&gamma_xy_my_id, 
               gamma_xy_my_id_pointer + gamma_xy_offset, 
               sizeof(uint64_t));
        memcpy(&gamma_xy_previous_id, 
               gamma_xy_previous_id_pointer + gamma_xy_offset,
               sizeof(uint64_t));
        triple_.AppendTriple(uint64_t(a_lambdas_my_id.Get(i)), uint64_t(a_lambdas_previous_id.Get(i)),
                             uint64_t(b_lambdas_my_id.Get(i)), uint64_t(b_lambdas_previous_id.Get(i)),
                             gamma_xy_my_id, gamma_xy_previous_id);
        gamma_xy_my_id_.Set(gamma_xy_my_id & 0x1, i);
        gamma_xy_previous_id_.Set(gamma_xy_previous_id & 0x1, i);
        
        gamma_xy_offset += sizeof(uint64_t);
      }
      backend_.GetSociumVerifier()->SetReady();
      assert(gamma_xy_offset == number_of_gamma_xy_bytes);
    }
  } else { // S2
    uint64_t empty = 0;
    size_t gamma_xy_offset = 0;
    uint8_t const* const gamma_xy_my_id_pointer = randoms_my_id.data();
    for(size_t i = 0; i != number_of_simd_values; ++i) {
      uint64_t gamma_xy_my_id;
      memcpy(&gamma_xy_my_id, 
             gamma_xy_my_id_pointer + gamma_xy_offset,
             sizeof(uint64_t));

      triple_.AppendTriple(uint64_t(a_lambdas_my_id.Get(i)), uint64_t(a_lambdas_previous_id.Get(i)),
                           uint64_t(b_lambdas_my_id.Get(i)), uint64_t(b_lambdas_previous_id.Get(i)),
                          gamma_xy_my_id, empty);
      gamma_xy_my_id_.Set(gamma_xy_my_id & 0x1, i);

      gamma_xy_offset += sizeof(uint64_t);
    }
    backend_.GetSociumVerifier()->SetReady();

    assert(gamma_xy_offset == number_of_gamma_xy_bytes);
  }
}

void SociumAndGate::EvaluateOnline() {
  using communication::MessageType::kSociumOnlineMultiplyGate;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<swift::BooleanWire>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<swift::BooleanWire>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<swift::BooleanWire>(parent_b_[0]);
  assert(b_wire);
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
  
  auto const& a_lambdas_my_id = a_wire->GetLambdasMyId();
  auto const& a_lambdas_previous_id = a_wire->GetLambdasPreviousId();
  auto const& a_values = a_wire->GetValues();
  auto const& b_lambdas_my_id = b_wire->GetLambdasMyId();
  auto const& b_lambdas_previous_id = b_wire->GetLambdasPreviousId();
  auto const& b_values = a_wire->GetValues();
  auto& out_lambdas_my_id = out_wire->GetMutableLambdasMyId();
  auto& out_lambdas_previous_id = out_wire->GetMutableLambdasPreviousId();
  auto& out_values = out_wire->GetMutableValues();
  
  BitVector<> m_my_id = 
    (a_values & b_lambdas_my_id) ^ (b_values & a_lambdas_my_id)
    ^ gamma_xy_my_id_ ^ out_lambdas_my_id; 
  BitVector<> m_previous_id = 
    (a_values & b_lambdas_previous_id) ^ (b_values & a_lambdas_previous_id)
    ^ gamma_xy_previous_id_ ^ out_lambdas_previous_id;
  BitVector<> m_both = m_my_id ^ m_previous_id;
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    verifier_s1_message_data_.AssignData(m_previous_id.GetData());
    multipy_hash_verifier->SetReady();
  } else if(my_id == 1) {
    //We are S1 so we send m_0+m_1 to S2 and S0
    {
      std::span<uint8_t const> payload(
        reinterpret_cast<uint8_t const*>(m_both.GetData().data()), 
        m_both.GetData().size());
      auto message = 
        communication::BuildMessage(kSociumOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
    }
    
    {
      std::span<uint8_t const> payload(
        reinterpret_cast<uint8_t const*>(m_both.GetData().data()), 
        m_both.GetData().size());
      auto message = 
        communication::BuildMessage(kSociumOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(0, message.Release());
    }
  } else if(my_id == 2) {
    //We are S2 so we send m_2 to S1, which is m_my_id
    {
      std::span<uint8_t const> payload(
        reinterpret_cast<uint8_t const*>(m_my_id.GetData().data()), 
        m_my_id.GetData().size());
      auto message = 
        communication::BuildMessage(kSociumOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(1, message.Release());
    }
  } else {
    assert(false);
  }
  
  {
    auto message = multiply_future_online_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    BitVector<> m_missing_part(payload->Data(), payload->size());
    if (my_id == 0) { // m_missing_part is m0 + m1
      out_values = m_previous_id ^ m_missing_part ^ (a_values & b_values);
    } else if (my_id == 1) {// m_missing_part is m2
      verifier_received_hash_data_.AssignData(m_missing_part.GetData());
      multipy_hash_verifier->SetReady();
      out_values = m_previous_id ^ m_my_id ^ m_missing_part ^ (a_values & b_values);
    } else if (my_id == 2) { // m_missing_part is m0 + m1
      out_values = m_my_id ^ m_missing_part ^ (a_values & b_values);
    } else {
      assert(false);
    }
  }
}

XorGate::XorGate(swift::BooleanWirePointer const& a, swift::BooleanWirePointer const& b)
    : TwoGate(a->GetBackend()) {
  size_t number_of_simd_values = a->GetNumberOfSimdValues();
  assert(number_of_simd_values == b->GetNumberOfSimdValues());
  parent_a_ = {std::move(a)};
  parent_b_ = {std::move(b)};

  output_wires_ = 
    {GetRegister().template EmplaceWire<swift::BooleanWire>(
      backend_,
      BitVector<>(number_of_simd_values, false),
      BitVector<>(number_of_simd_values, false),
      BitVector<>(number_of_simd_values, false))};
}

void XorGate::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<swift::BooleanWire>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<swift::BooleanWire>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<swift::BooleanWire>(parent_b_[0]);
  assert(b_wire);

  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();
  
  auto const& a_lambdas_my_id = a_wire->GetLambdasMyId();
  auto const& a_lambdas_previous_id = a_wire->GetLambdasPreviousId();
  auto const& b_lambdas_my_id = b_wire->GetLambdasMyId();
  auto const& b_lambdas_previous_id = b_wire->GetLambdasPreviousId();
  auto& out_lambdas_my_id = out_wire->GetMutableLambdasMyId();
  auto& out_lambdas_previous_id = out_wire->GetMutableLambdasPreviousId();
  
  out_lambdas_my_id = a_lambdas_my_id ^ b_lambdas_my_id;
  out_lambdas_previous_id = a_lambdas_previous_id ^ b_lambdas_previous_id;
  
  out_wire->SetSetupIsReady();
}

void XorGate::EvaluateOnline() {
  auto out_wire = std::dynamic_pointer_cast<swift::BooleanWire>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<swift::BooleanWire>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<swift::BooleanWire>(parent_b_[0]);
  assert(b_wire);
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
  
  auto const& a_values = a_wire->GetValues();
  auto const& b_values = a_wire->GetValues();
  auto& out_values = out_wire->GetMutableValues();
  
  out_values = a_values ^ b_values;
}

swift::BooleanWirePointer MsbAdd(std::vector<swift::BooleanWirePointer> const& a, 
                                 std::vector<swift::BooleanWirePointer> const& b) {
  using namespace std::literals::string_literals;
  std::string path;
  assert(a.size() > 0);
  assert(a.size() == b.size());
  size_t bitlen = a.size();
  Backend& backend = a[0]->GetBackend();
  {
    switch(bitlen) {
      case 8: {
        path = std::string(encrypto::motion::kRootDir) + "/circuits/int/msb_adder_8_log.bristol"s;
        break;
      }
      case 16: {
        path = std::string(encrypto::motion::kRootDir) + "/circuits/int/msb_adder_16_log.bristol"s;
        break;
      }
      case 32: {
        path = std::string(encrypto::motion::kRootDir) + "/circuits/int/msb_adder_32_log.bristol"s;
        break;
      }
      case 64: {
        path = std::string(encrypto::motion::kRootDir) + "/circuits/int/msb_adder_64_log.bristol"s;
        break;
      }
    }
  }
  std::ifstream stream(path);
  assert(stream.is_open());
  assert(stream.good());
  size_t number_of_gates, number_of_wires;
  stream >> number_of_gates >> number_of_wires;

  std::vector<std::string> line_vector;
  std::string line;
  std::getline(stream, line);  // skip \n at the end of the first line
  size_t number_of_wires_parent_a = 0;
  [[maybe_unused]] size_t number_of_wires_parent_b = 0;
  size_t number_of_output_wires = 0;
  {
    std::string second_line;
    std::getline(stream, second_line);
    std::stringstream ss(second_line);
    while (std::getline(ss, line, ' ')) {
      line_vector.emplace_back(std::move(line));
      line.clear();
    }
    number_of_wires_parent_a = std::stoull(line_vector[0]);
    if (line_vector.size() == 2) {
      number_of_output_wires = std::stoull(line_vector[1]);
    } else if (line_vector.size() == 3) {
      number_of_wires_parent_b = std::stoull(line_vector[1]);
      number_of_output_wires = std::stoull(line_vector[2]);
    } else {
      throw std::runtime_error(
          std::string("Unexpected number of values: " 
                      + std::to_string(line_vector.size()) + "\n"));
    }
    line.clear();
    line_vector.clear();
  }
  assert(number_of_wires_parent_a == number_of_wires_parent_b);
  assert(number_of_output_wires == 1);

  std::getline(stream, line);
  assert(line.empty());
  std::vector<swift::BooleanWirePointer> wires(number_of_wires);
  assert(a.size() == number_of_wires_parent_a);
  assert(b.size() == number_of_wires_parent_b);
  for(size_t i = 0; i != a.size(); ++i) {
    wires[i] = a[i];
    wires[i + number_of_wires_parent_a] = b[i];
    }
  // read line
  while (std::getline(stream, line)) {
    if (line.size() == 0) continue;
    std::stringstream ss(line);
    size_t gate_inputs, gate_outputs, a_index, b_index, out_index;
    std::string type;
    ss >> gate_inputs >> gate_outputs >> a_index >> b_index >> out_index >> type;
    
    assert(2 == gate_inputs);
    assert(1 == gate_outputs);
    auto const& a_wire = wires[a_index];
    auto const& b_wire = wires[b_index];
    
    if(type == "XOR"s) {
      wires[out_index] = 
        std::dynamic_pointer_cast<swift::BooleanWire>(
          backend.GetRegister()->EmplaceGate<swift::XorGate>(a_wire, b_wire)->
            GetOutputWires()[0]);
      assert(wires[out_index]);
    }
    else if(type == "AND"s) {
      wires[out_index] = 
        std::dynamic_pointer_cast<swift::BooleanWire>(
          backend.GetRegister()->EmplaceGate<swift::AndGate>(a_wire, b_wire)->
            GetOutputWires()[0]);
      assert(wires[out_index]);
    }
    else {
      assert(false);
    }
  }
  return wires[number_of_wires - number_of_output_wires];
}

swift::BooleanWirePointer SociumMsbAdd(std::vector<swift::BooleanWirePointer> const& a, 
                                 std::vector<swift::BooleanWirePointer> const& b) {
  using namespace std::literals::string_literals;
  std::string path;
  assert(a.size() > 0);
  assert(a.size() == b.size());
  size_t bitlen = a.size();
  Backend& backend = a[0]->GetBackend();
  {
    switch(bitlen) {
      case 8: {
        path = std::string(encrypto::motion::kRootDir) + "/circuits/int/msb_adder_8_log.bristol"s;
        break;
      }
      case 16: {
        path = std::string(encrypto::motion::kRootDir) + "/circuits/int/msb_adder_16_log.bristol"s;
        break;
      }
      case 32: {
        path = std::string(encrypto::motion::kRootDir) + "/circuits/int/msb_adder_32_log.bristol"s;
        break;
      }
      case 64: {
        path = std::string(encrypto::motion::kRootDir) + "/circuits/int/msb_adder_64_log.bristol"s;
        break;
      }
    }
  }
  std::ifstream stream(path);
  assert(stream.is_open());
  assert(stream.good());
  size_t number_of_gates, number_of_wires;
  stream >> number_of_gates >> number_of_wires;

  std::vector<std::string> line_vector;
  std::string line;
  std::getline(stream, line);  // skip \n at the end of the first line
  size_t number_of_wires_parent_a = 0;
  [[maybe_unused]] size_t number_of_wires_parent_b = 0;
  size_t number_of_output_wires = 0;
  {
    std::string second_line;
    std::getline(stream, second_line);
    std::stringstream ss(second_line);
    while (std::getline(ss, line, ' ')) {
      line_vector.emplace_back(std::move(line));
      line.clear();
    }
    number_of_wires_parent_a = std::stoull(line_vector[0]);
    if (line_vector.size() == 2) {
      number_of_output_wires = std::stoull(line_vector[1]);
    } else if (line_vector.size() == 3) {
      number_of_wires_parent_b = std::stoull(line_vector[1]);
      number_of_output_wires = std::stoull(line_vector[2]);
    } else {
      throw std::runtime_error(
          std::string("Unexpected number of values: " 
                      + std::to_string(line_vector.size()) + "\n"));
    }
    line.clear();
    line_vector.clear();
  }
  assert(number_of_wires_parent_a == number_of_wires_parent_b);
  assert(number_of_output_wires == 1);

  std::getline(stream, line);
  assert(line.empty());
  std::vector<swift::BooleanWirePointer> wires(number_of_wires);
  assert(a.size() == number_of_wires_parent_a);
  assert(b.size() == number_of_wires_parent_b);
  for(size_t i = 0; i != a.size(); ++i) {
    wires[i] = a[i];
    wires[i + number_of_wires_parent_a] = b[i];
    }
  // read line
  while (std::getline(stream, line)) {
    if (line.size() == 0) continue;
    std::stringstream ss(line);
    size_t gate_inputs, gate_outputs, a_index, b_index, out_index;
    std::string type;
    ss >> gate_inputs >> gate_outputs >> a_index >> b_index >> out_index >> type;
    
    assert(2 == gate_inputs);
    assert(1 == gate_outputs);
    auto const& a_wire = wires[a_index];
    auto const& b_wire = wires[b_index];
    
    if(type == "XOR"s) {
      wires[out_index] = 
        std::dynamic_pointer_cast<swift::BooleanWire>(
          backend.GetRegister()->EmplaceGate<swift::XorGate>(a_wire, b_wire)->
            GetOutputWires()[0]);
      assert(wires[out_index]);
    }
    else if(type == "AND"s) {
      wires[out_index] = 
        std::dynamic_pointer_cast<swift::BooleanWire>(
          backend.GetRegister()->EmplaceGate<swift::SociumAndGate>(a_wire, b_wire)->
            GetOutputWires()[0]);
      assert(wires[out_index]);
    }
    else {
      assert(false);
    }
  }
  return wires[number_of_wires - number_of_output_wires];
}

template<typename T>
MatrixConversionGate<T>::MatrixConversionGate(
  boost::numeric::ublas::matrix<swift::WirePointer<T>> wires) 
: Base(wires(0, 0)->GetBackend()), wires_(std::move(wires)) {
  
  size_t n = wires_.size1();
  size_t m = wires_.size2();
  size_t number_of_simd_values = wires_(0, 0)->GetNumberOfSimdValues();

  output_wires_ = 
    {GetRegister().template EmplaceWire<swift::MatrixWire<T>>(backend_, n, m, number_of_simd_values)};
  
}

template<typename T>
void MatrixConversionGate<T>::EvaluateSetup() {
  auto matrix_out_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto& out_lambda_my_id_matrices = matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_lambda_previous_id_matrices = matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  size_t const number_of_simd_values = out_lambda_my_id_matrices.size();
  assert(out_lambda_previous_id_matrices.size() == number_of_simd_values);
  
  size_t const m = wires_.size1();
  size_t const n = wires_.size2();
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      swift::WirePointer<T> w = wires_(i, j);
      w->GetSetupReadyCondition()->Wait();
      auto const& data = w->GetData();
      assert(data.lambda_my_id.size() == number_of_simd_values);
      assert(data.lambda_previous_id.size() == number_of_simd_values);
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        out_lambda_my_id_matrices[s](i, j) = data.lambda_my_id[s];
        out_lambda_previous_id_matrices[s](i, j) = data.lambda_previous_id[s];
      }
    }
  }
  matrix_out_wire->SetSetupIsReady();
}

template<typename T>
void MatrixConversionGate<T>::EvaluateOnline() {
  auto matrix_out_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
  size_t const number_of_simd_values = out_value_matrices.size();
  
  for(size_t i = 0; i != wires_.size1(); ++i) {
    for(size_t j = 0; j != wires_.size2(); ++j) {
      swift::WirePointer<T> w = wires_(i, j);
      w->GetIsReadyCondition().Wait();
      auto const& data = w->GetData();
      assert(data.values.size() == number_of_simd_values);
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        out_value_matrices[s](i, j) = data.values[s];
      }
    }
  }
}

template class MatrixConversionGate<std::uint8_t>;
template class MatrixConversionGate<std::uint16_t>;
template class MatrixConversionGate<std::uint32_t>;
template class MatrixConversionGate<std::uint64_t>;

template<typename T>
MatrixReconversionGate<T>::MatrixReconversionGate(swift::MatrixWirePointer<T> const& matrix_wire) 
: Base(matrix_wire->GetBackend()) {
  
  auto const& value_matrices = matrix_wire->GetMutableValueMatrices(); 
    
  size_t const number_of_simd_values = value_matrices.size();
  size_t const m = value_matrices[0].size1();
  size_t const n = value_matrices[0].size2();
  wire_matrix_.resize(m, n);
  
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      wire_matrix_(i, j) = 
        GetRegister().template EmplaceWire<swift::Wire<T>>(
          backend_, number_of_simd_values, 
          std::vector<T>(number_of_simd_values),
          std::vector<T>(number_of_simd_values),
          std::vector<T>(number_of_simd_values));
    }
  }

  matrix_input_wire_ = std::move(matrix_wire);
}

template<typename T>
void MatrixReconversionGate<T>::EvaluateSetup() {
  auto& in_lambda_my_id_matrices = matrix_input_wire_->GetMutableLambdaMyIdMatrices();
  auto& in_lambda_previous_id_matrices = matrix_input_wire_->GetMutableLambdaPreviousIdMatrices();
  size_t number_of_simd_values = in_lambda_my_id_matrices.size();
  assert(in_lambda_previous_id_matrices.size() == number_of_simd_values);
  
  matrix_input_wire_->GetSetupReadyCondition()->Wait();
  
  size_t m = in_lambda_my_id_matrices[0].size1();
  size_t n = in_lambda_my_id_matrices[0].size2();
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      auto w = wire_matrix_(i, j);
      auto& data = w->GetMutableData();
      assert(data.lambda_my_id.size() == number_of_simd_values);
      assert(data.lambda_previous_id.size() == number_of_simd_values);
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        assert(in_lambda_my_id_matrices[s].size1() == m);
        assert(in_lambda_my_id_matrices[s].size2() == n);
        assert(in_lambda_previous_id_matrices[s].size1() == m);
        assert(in_lambda_previous_id_matrices[s].size2() == n);
        data.lambda_my_id[s] = in_lambda_my_id_matrices[s](i, j);
        data.lambda_previous_id[s] = in_lambda_previous_id_matrices[s](i, j);
      }
      w->SetSetupIsReady();
    }
  }
}

template<typename T>
void MatrixReconversionGate<T>::EvaluateOnline() {
  auto& in_value_matrices = matrix_input_wire_->GetMutableValueMatrices();
  size_t number_of_simd_values = in_value_matrices.size();
  size_t m = in_value_matrices[0].size1();
  size_t n = in_value_matrices[0].size2();
  matrix_input_wire_->GetIsReadyCondition().Wait();
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      auto w = wire_matrix_(i, j);
      auto& data = w->GetMutableData();
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        data.values[s] = in_value_matrices[s](i, j);
      }
      //The wires are not updated through the gate executor, so we set online finished here
      w->SetOnlineFinished();
    }
  }
}

template class MatrixReconversionGate<std::uint8_t>;
template class MatrixReconversionGate<std::uint16_t>;
template class MatrixReconversionGate<std::uint32_t>;
template class MatrixReconversionGate<std::uint64_t>;

template<typename T>
MatrixSimdReconversionGate<T>::MatrixSimdReconversionGate(
  swift::MatrixWirePointer<T> const& matrix_wire) 
: Base(matrix_wire->GetBackend()) {
  
  auto const& value_matrices = matrix_wire->GetMutableValueMatrices(); 
    
  size_t const number_of_simd_values = 
    value_matrices.size() * value_matrices[0].size1() * value_matrices[0].size2();
  
  wire_ = GetRegister().template EmplaceWire<swift::Wire<T>>(
    backend_, number_of_simd_values, 
    std::vector<T>(number_of_simd_values),
    std::vector<T>(number_of_simd_values),
    std::vector<T>(number_of_simd_values));

  matrix_input_wire_ = std::move(matrix_wire);
}

template<typename T>
void MatrixSimdReconversionGate<T>::EvaluateSetup() {
  auto& in_lambda_my_id_matrices = matrix_input_wire_->GetMutableLambdaMyIdMatrices();
  auto& in_lambda_previous_id_matrices = matrix_input_wire_->GetMutableLambdaPreviousIdMatrices();
  
  matrix_input_wire_->GetSetupReadyCondition()->Wait();
  
  size_t const number_of_matrix_simd_values = in_lambda_my_id_matrices.size();
  assert(in_lambda_previous_id_matrices.size() == number_of_matrix_simd_values);
  size_t const m = in_lambda_my_id_matrices[0].size1();
  size_t const n = in_lambda_my_id_matrices[0].size2();
  auto& data = wire_->GetMutableData();
  assert(data.lambda_my_id.size() == number_of_matrix_simd_values * m * n);
  assert(data.lambda_previous_id.size() == number_of_matrix_simd_values * m * n);
  {
    size_t offset = 0;
    for(size_t s = 0; s != number_of_matrix_simd_values; ++s) {
      for(size_t i = 0; i != m; ++i) {
        for(size_t j = 0; j != n; ++j) {
          assert(in_lambda_my_id_matrices[s].size1() == m);
          assert(in_lambda_my_id_matrices[s].size2() == n);
          assert(in_lambda_previous_id_matrices[s].size1() == m);
          assert(in_lambda_previous_id_matrices[s].size2() == n);
          data.lambda_my_id[offset] = in_lambda_my_id_matrices[s](i, j);
          data.lambda_previous_id[offset] = in_lambda_previous_id_matrices[s](i, j);
          ++offset;
        }
      }
    }
    assert(offset == m * n * number_of_matrix_simd_values);
  }
  wire_->SetSetupIsReady();
}

template<typename T>
void MatrixSimdReconversionGate<T>::EvaluateOnline() {
  auto& in_value_matrices = matrix_input_wire_->GetMutableValueMatrices();
  size_t number_of_matrix_simd_values = in_value_matrices.size();
  size_t m = in_value_matrices[0].size1();
  size_t n = in_value_matrices[0].size2();
  matrix_input_wire_->GetIsReadyCondition().Wait();
  
  auto& data = wire_->GetMutableData();
  {
    size_t offset = 0;
    for(size_t s = 0; s != number_of_matrix_simd_values; ++s) {
      for(size_t i = 0; i != m; ++i) {
        for(size_t j = 0; j != n; ++j) {
          assert(in_value_matrices[s].size1() == m);
          assert(in_value_matrices[s].size2() == n);
          data.values[offset] = in_value_matrices[s](i, j);
          ++offset;
        }
      }
    }
    assert(offset == number_of_matrix_simd_values * m * n);
  }
  wire_->SetOnlineFinished();
}

template class MatrixSimdReconversionGate<std::uint8_t>;
template class MatrixSimdReconversionGate<std::uint16_t>;
template class MatrixSimdReconversionGate<std::uint32_t>;
template class MatrixSimdReconversionGate<std::uint64_t>;


namespace {

template<typename T>
std::vector<boost::numeric::ublas::matrix<T>>
CreateMatrices(size_t m, size_t n, size_t number_of_simd_values) {
  std::vector<boost::numeric::ublas::matrix<T>> result;
  result.reserve(number_of_simd_values);
  for(size_t i = 0; i != number_of_simd_values; ++i) {
    result.emplace_back(m, n);
  }
  return result;
}

template<typename T>
std::vector<uint8_t> SerializeMatrices(
  std::vector<boost::numeric::ublas::matrix<T>> const& matrices) {

  std::vector<uint8_t> result;
  size_t number_of_simd_values = matrices.size();
  size_t m = matrices[0].size1();
  size_t n = matrices[0].size2();
  result.reserve(number_of_simd_values * m * n * sizeof(T));
  for(size_t s = 0; s != number_of_simd_values; ++s) {
    for(size_t i = 0; i != m; ++i) {
      for(size_t j = 0; j != n; ++j) {
        T tmp = matrices[s](i, j);
        for(size_t b = 0; b != sizeof(T); ++b) {
          result.emplace_back(uint8_t(tmp >> (b * CHAR_BIT)));
        }
      }
    }
  }
  return result;
}

template<typename T>
void DeserializeMatrices(std::vector<boost::numeric::ublas::matrix<T>>& matrices, 
                         std::span<const std::uint8_t> message) {
  size_t number_of_simd_values = matrices.size();
  size_t m = matrices[0].size1();
  size_t n = matrices[0].size2();
  auto message_it = message.begin();
  for(size_t s = 0; s != number_of_simd_values; ++s) {
    for(size_t i = 0; i != m; ++i) {
      for(size_t j = 0; j != n; ++j) {
        T tmp = 0;
        for(size_t b = 0; b != sizeof(T); ++b, ++message_it) {
          assert(message_it != message.end());
          tmp |= T(*message_it) << (b * CHAR_BIT);
        }
        matrices[s](i, j) = tmp;
      }
    }
  }
  assert(message_it == message.end());
}

} // namespace (anonymous)


template<typename T>
MatrixMultiplicationGate<T>::MatrixMultiplicationGate(
  swift::MatrixWirePointer<T> matrix_a, swift::MatrixWirePointer<T> matrix_b)
: TwoGate(matrix_a->GetBackend()),
  triple_(backend_.GetSwiftVerifier()->ReserveMatrixTriples128(matrix_a->GetNumberOfSimdValues())) {
  using communication::MessageType::kSwiftSetupMultiplyGate;
  using communication::MessageType::kSwiftOnlineMultiplyGate;
  size_t const u = matrix_a->GetMutableLambdaMyIdMatrices()[0].size1();
  size_t const v = matrix_b->GetMutableLambdaMyIdMatrices()[0].size2();
  size_t const number_of_simd_values = matrix_a->GetNumberOfSimdValues();
  assert(matrix_a->GetMutableLambdaMyIdMatrices()[0].size2() == matrix_b->GetMutableLambdaMyIdMatrices()[0].size1());
  assert(matrix_a->GetMutableLambdaPreviousIdMatrices()[0].size2() == matrix_b->GetMutableLambdaPreviousIdMatrices()[0].size1());
  assert(matrix_b->GetNumberOfSimdValues() == number_of_simd_values);
  
  parent_a_ = {std::move(matrix_a)};
  parent_b_ = {std::move(matrix_b)};
  
  output_wires_ = 
    {GetRegister().template EmplaceWire<swift::MatrixWire<T>>(backend_, u, v, number_of_simd_values)};
    
  matrix_gamma_xy_my_id_ = CreateMatrices<T>(u, v, number_of_simd_values);
  matrix_gamma_xy_previous_id_ = CreateMatrices<T>(u, v, number_of_simd_values);

  uint64_t my_id = GetCommunicationLayer().GetMyId();
  uint64_t previous_id = (my_id + 2) % 3;
  
  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  matrix_multiply_future_setup_ =
    message_manager.RegisterReceive(previous_id, kSwiftSetupMultiplyGate, gate_id_);
    
  if(my_id == 0) {
    matrix_multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftOnlineMultiplyGate, gate_id_);
  } else if(my_id == 1) {
    matrix_multiply_future_online_ = 
      message_manager.RegisterReceive(2, kSwiftOnlineMultiplyGate, gate_id_);
  } else if(my_id == 2) {
    matrix_multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftOnlineMultiplyGate, gate_id_);
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    //We are S_0, so we reserve hash memory for the hash we will receive from S2
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        u * v * number_of_simd_values * sizeof(T), 2);
    //we also reserve memory for the hash we will be sending to S1 and S2
    verifier_s1_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        u * v * number_of_simd_values * sizeof(T), 1);
    verifier_s2_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        u * v * number_of_simd_values * sizeof(T), 2);
  } else {
    //We are S1 or S2 and thus will receive a hash from S0;
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        u * v * number_of_simd_values * sizeof(T), 0);
  }
  if(my_id == 2) {
    //We reserve memory for the hash we will be sending to S0
    verifier_s2_message_data_ = 
      multipy_hash_verifier->ReserveHashMessage(
        u * v * number_of_simd_values * sizeof(T), 0);
  }
}

template<typename T>
void MatrixMultiplicationGate<T>::EvaluateSetup() {
  using boost::numeric::ublas::matrix;
  using communication::MessageType::kSwiftSetupMultiplyGate;
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  auto matrix_out_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_a_[0]);
  assert(matrix_a_wire);
  auto matrix_b_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_b_[0]);
  assert(matrix_b_wire);
  
  auto& a_my_id_lambda_matrices = matrix_a_wire->GetMutableLambdaMyIdMatrices();
  auto& a_previous_id_lambda_matrices = matrix_a_wire->GetMutableLambdaPreviousIdMatrices();
  auto& b_my_id_lambda_matrices = matrix_b_wire->GetMutableLambdaMyIdMatrices();
  auto& b_previous_id_lambda_matrices = matrix_b_wire->GetMutableLambdaPreviousIdMatrices();
  auto& out_my_id_lambda_matrices = matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_previous_id_lambda_matrices = matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  
  size_t const number_of_simd_values = matrix_a_wire->GetNumberOfSimdValues();
  size_t const u = a_my_id_lambda_matrices[0].size1();
  size_t const w = a_my_id_lambda_matrices[0].size2();
  size_t const v = b_my_id_lambda_matrices[0].size2();
  
  size_t const u_v_elements = u * v * number_of_simd_values;
  
  size_t const number_of_gamma_xy_bytes = u_v_elements * sizeof(UInt128);
  size_t const number_of_lambda_z_bytes = u_v_elements * sizeof(T);
  size_t const random_bytes = number_of_gamma_xy_bytes + number_of_lambda_z_bytes;
  
  auto AssignToMatrix = [](auto& mat, uint8_t const* const data_pointer) {
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
  
  auto AssignFromMatrix = [](uint8_t* const data_pointer, auto const& mat) {
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
  
  //We assume the role of S_i and generate the random numbers we share with S_i+1
  auto& rng_i = backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
  //We assume the role of S_i+1 and generate the random numbers we share with S_i
  auto& rng_i_minus_1 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
  //randoms_my_id contains gamma_xy_my_id followed by lambda_z_my_id
  std::vector<uint8_t> randoms_my_id = 
    rng_i.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
  //randoms_previous_id contains gamma_xy_previous_id followed by lambda_z_previous_id
  std::vector<uint8_t> randoms_previous_id = 
    rng_i_minus_1.template GetUnsigned<uint8_t>(gate_id_, random_bytes);

  {
    size_t lambda_z_offset = 0;
    uint8_t const* const lambda_z_my_id_pointer = 
      randoms_my_id.data() + number_of_gamma_xy_bytes;
    uint8_t const* const lambda_z_previous_id_pointer = 
      randoms_previous_id.data() + number_of_gamma_xy_bytes;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      AssignToMatrix(out_my_id_lambda_matrices[s], 
                     lambda_z_my_id_pointer + lambda_z_offset);
      AssignToMatrix(out_previous_id_lambda_matrices[s], 
                     lambda_z_previous_id_pointer + lambda_z_offset);
     lambda_z_offset += u * v * sizeof(T);
    }
    assert(lambda_z_offset == number_of_lambda_z_bytes);
  }
  matrix_out_wire->SetSetupIsReady();
  
  //Extend input lambdas
  std::vector<matrix<UInt128>> extended_a_my_id_lambda_matrices;
  std::vector<matrix<UInt128>> extended_a_previous_id_lambda_matrices;
  std::vector<matrix<UInt128>> extended_b_my_id_lambda_matrices;
  std::vector<matrix<UInt128>> extended_b_previous_id_lambda_matrices;
  extended_a_my_id_lambda_matrices.reserve(number_of_simd_values);
  extended_a_previous_id_lambda_matrices.reserve(number_of_simd_values);
  extended_b_my_id_lambda_matrices.reserve(number_of_simd_values);
  extended_b_previous_id_lambda_matrices.reserve(number_of_simd_values);
  matrix_a_wire->GetSetupReadyCondition()->Wait();
  matrix_b_wire->GetSetupReadyCondition()->Wait();
  for(size_t s = 0; s != number_of_simd_values; ++s) {
    [[maybe_unused]] size_t const u_s = a_my_id_lambda_matrices[s].size1();
    [[maybe_unused]] size_t const w_s = a_my_id_lambda_matrices[s].size2();
    [[maybe_unused]] size_t const v_s = b_my_id_lambda_matrices[s].size2();
    
    assert(u_s == u);
    assert(w_s == w);
    assert(v_s == v);
    assert(a_my_id_lambda_matrices[s].size1() == u);
    assert(a_my_id_lambda_matrices[s].size2() == w);
    assert(b_my_id_lambda_matrices[s].size1() == w);
    assert(b_my_id_lambda_matrices[s].size2() == v);
    assert(out_my_id_lambda_matrices[s].size1() == u);
    assert(out_my_id_lambda_matrices[s].size2() == v);
    assert(a_previous_id_lambda_matrices[s].size1() == u);
    assert(a_previous_id_lambda_matrices[s].size2() == w);
    assert(b_previous_id_lambda_matrices[s].size1() == w);
    assert(b_previous_id_lambda_matrices[s].size2() == v);
    assert(out_previous_id_lambda_matrices[s].size1() == u);
    assert(out_previous_id_lambda_matrices[s].size2() == v);
    
    extended_a_my_id_lambda_matrices.emplace_back(u, w);
    extended_a_previous_id_lambda_matrices.emplace_back(u, w);
    extended_b_my_id_lambda_matrices.emplace_back(w, v);
    extended_b_previous_id_lambda_matrices.emplace_back(w, v);
    
    for(size_t i = 0; i != u; ++i) {
      for(size_t j = 0; j != w; ++j) {
        extended_a_my_id_lambda_matrices[s](i, j) =
          a_my_id_lambda_matrices[s](i, j);
        extended_a_previous_id_lambda_matrices[s](i, j) =
          a_previous_id_lambda_matrices[s](i, j);
      }
    }
    
    for(size_t i = 0; i != w; ++i) {
      for(size_t j = 0; j != v; ++j) {
        extended_b_my_id_lambda_matrices[s](i, j) =
          b_my_id_lambda_matrices[s](i, j);
        extended_b_previous_id_lambda_matrices[s](i, j) =
          b_previous_id_lambda_matrices[s](i, j);
      }
    }
  }
  
  {
    size_t offset = 0;
    uint8_t const* const alpha_i_pointer = randoms_my_id.data();
    uint8_t const* const alpha_i_minus_1_pointer = randoms_previous_id.data();
    uint8_t* const c_i_pointer = randoms_my_id.data();
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      matrix<UInt128> alpha_i(u, v), alpha_i_minus_1(u, v);
      AssignToMatrix(alpha_i, alpha_i_pointer + offset);
      AssignToMatrix(alpha_i_minus_1, alpha_i_minus_1_pointer + offset);
      matrix<UInt128> c_i = 
        prod(extended_a_my_id_lambda_matrices[s], extended_b_my_id_lambda_matrices[s]) +
        prod(extended_a_my_id_lambda_matrices[s], extended_b_previous_id_lambda_matrices[s]) +
        prod(extended_a_previous_id_lambda_matrices[s], extended_b_my_id_lambda_matrices[s]) +
        alpha_i - alpha_i_minus_1;
      AssignFromMatrix(c_i_pointer + offset, c_i);
      offset += u * v * sizeof(UInt128);
    }
    assert(offset == number_of_gamma_xy_bytes);
  }
  //Now the c_i values are in randoms_my_id[0,...,number_of_gamma_xy_bytes]
  
  {
    auto payload = std::span<uint8_t const>(randoms_my_id.data(), number_of_gamma_xy_bytes);
    auto message = communication::BuildMessage(kSwiftSetupMultiplyGate, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  
  {
    auto message = matrix_multiply_future_setup_.get();
    const auto payload = communication::GetMessage(message.data())->payload();
    auto received_data = std::span<uint8_t const>{payload->Data(), payload->size()};
    {
      size_t gamma_xy_offset = 0;
      uint8_t const* const gamma_xy_my_id_pointer = 
        randoms_my_id.data();
      uint8_t const* const gamma_xy_previous_id_pointer = 
        received_data.data();
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        matrix<UInt128> gamma_xy_my_id(u, v), gamma_xy_previous_id(u, v);
        AssignToMatrix(gamma_xy_my_id, 
                       gamma_xy_my_id_pointer + gamma_xy_offset);
        AssignToMatrix(gamma_xy_previous_id, 
                       gamma_xy_previous_id_pointer + gamma_xy_offset);
        triple_.AppendTriple(
          extended_a_my_id_lambda_matrices[s], 
          extended_a_previous_id_lambda_matrices[s],
          extended_b_my_id_lambda_matrices[s], 
          extended_b_previous_id_lambda_matrices[s],
          gamma_xy_my_id, 
          gamma_xy_previous_id);
        for(size_t i = 0; i != u; ++i) {
          for(size_t j = 0; j != v; ++j) {
            matrix_gamma_xy_my_id_[s](i, j) = 
              T(gamma_xy_my_id(i, j));
            matrix_gamma_xy_previous_id_[s](i, j) = 
              T(gamma_xy_previous_id(i, j));
          }
        }
        gamma_xy_offset += u * v * sizeof(UInt128);
      }
      backend_.GetSwiftVerifier()->SetReady();
      assert(gamma_xy_offset == number_of_gamma_xy_bytes);
    }
  }
}

template<typename T>
void MatrixMultiplicationGate<T>::EvaluateOnline() {
  using communication::MessageType::kSwiftOnlineMultiplyGate;
  using boost::numeric::ublas::matrix;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_a_[0]);
  assert(matrix_a_wire);
  auto matrix_b_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_b_[0]);
  assert(matrix_b_wire);
  size_t number_of_simd_values = matrix_a_wire->GetNumberOfSimdValues();
  assert(matrix_b_wire->GetNumberOfSimdValues() == number_of_simd_values);
  assert(matrix_out_wire->GetNumberOfSimdValues() == number_of_simd_values);
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
  
  auto& a_value_matrices = matrix_a_wire->GetMutableValueMatrices();
  auto& a_my_id_lambda_matrices = matrix_a_wire->GetMutableLambdaMyIdMatrices();
  auto& a_previous_id_lambda_matrices = matrix_a_wire->GetMutableLambdaPreviousIdMatrices();
  auto& b_value_matrices = matrix_b_wire->GetMutableValueMatrices();
  auto& b_my_id_lambda_matrices = matrix_b_wire->GetMutableLambdaMyIdMatrices();
  auto& b_previous_id_lambda_matrices = matrix_b_wire->GetMutableLambdaPreviousIdMatrices();
  auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
  auto& out_my_id_lambda_matrices = matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_previous_id_lambda_matrices = matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  
  size_t const u = a_my_id_lambda_matrices[0].size1();
  size_t const v = b_my_id_lambda_matrices[0].size2();
  
  std::vector<matrix<T>> m_my_id, m_previous_id;
  m_my_id.reserve(number_of_simd_values);
  m_previous_id.reserve(number_of_simd_values);
  
  for(size_t s = 0; s != number_of_simd_values; ++s) {
    m_my_id.emplace_back(
      prod(a_value_matrices[s], b_my_id_lambda_matrices[s])
      + prod(a_my_id_lambda_matrices[s], b_value_matrices[s])
      + matrix_gamma_xy_my_id_[s] - out_my_id_lambda_matrices[s]);
    m_previous_id.emplace_back( 
      prod(a_value_matrices[s], b_previous_id_lambda_matrices[s])
      + prod(a_previous_id_lambda_matrices[s], b_value_matrices[s])
      + matrix_gamma_xy_previous_id_[s] - out_previous_id_lambda_matrices[s]);
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    verifier_s1_message_data_.AssignData(m_previous_id);
    multipy_hash_verifier->SetReady();
    verifier_s2_message_data_.AssignData(m_my_id);
    multipy_hash_verifier->SetReady();
  }
  else if(my_id == 1) {
    //We are S1 so we send m_0 to S2, which is m_previous_id
    //and m_1 to S0, which is m_my_id
    {
      auto payload = SerializeMatrices(m_previous_id);
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
    }
    
    {
      auto payload = SerializeMatrices(m_my_id);
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(0, message.Release());
    }
  } else if(my_id == 2) {
    //We are S2 so we send m_2 to S1, which is m_my_id
    //and H(m_1) which is H(m_previous_id)
    {
      auto payload = SerializeMatrices(m_my_id);
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(1, message.Release());
    }
    verifier_s2_message_data_.AssignData(m_previous_id);
    multipy_hash_verifier->SetReady();
  } else {
    assert(false);
  }
  
  {
    auto message = matrix_multiply_future_online_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    std::vector<matrix<T>> m_missing_id = 
      CreateMatrices<T>(u, v, number_of_simd_values);
    DeserializeMatrices(
      m_missing_id, std::span<uint8_t const>{payload->Data(), payload->size()});
    verifier_received_hash_data_.AssignData(m_missing_id);
    multipy_hash_verifier->SetReady();
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      out_value_matrices[s] = 
        m_previous_id[s] + m_my_id[s] + m_missing_id[s]
        + prod(a_value_matrices[s], b_value_matrices[s]);
    }
  }
}

template class MatrixMultiplicationGate<std::uint8_t>;
template class MatrixMultiplicationGate<std::uint16_t>;
template class MatrixMultiplicationGate<std::uint32_t>;
template class MatrixMultiplicationGate<std::uint64_t>;

template<typename T>
FpaMatrixMultiplicationGate<T>::FpaMatrixMultiplicationGate(
  swift::MatrixWirePointer<T> matrix_a, swift::MatrixWirePointer<T> matrix_b)
: TwoGate(matrix_a->GetBackend()),
  triple_(backend_.GetSwiftVerifier()->ReserveMatrixTriples128(matrix_a->GetNumberOfSimdValues())),
  truncation_pairs_(backend_.GetSwiftTruncation()->AddTruncationPairs(
    matrix_a->GetNumberOfSimdValues()
    * matrix_a->GetMutableLambdaMyIdMatrices()[0].size1()
    * matrix_b->GetMutableLambdaMyIdMatrices()[0].size2())) {
  using communication::MessageType::kSwiftSetupMultiplyGate;
  using communication::MessageType::kSwiftOnlineMultiplyGate;
  size_t const u = matrix_a->GetMutableLambdaMyIdMatrices()[0].size1();
  size_t const v = matrix_b->GetMutableLambdaMyIdMatrices()[0].size2();
  size_t const number_of_simd_values = matrix_a->GetNumberOfSimdValues();
  assert(matrix_a->GetMutableLambdaMyIdMatrices()[0].size2() == matrix_b->GetMutableLambdaMyIdMatrices()[0].size1());
  assert(matrix_a->GetMutableLambdaPreviousIdMatrices()[0].size2() == matrix_b->GetMutableLambdaPreviousIdMatrices()[0].size1());
  assert(matrix_b->GetNumberOfSimdValues() == number_of_simd_values);
  
  parent_a_ = {std::move(matrix_a)};
  parent_b_ = {std::move(matrix_b)};
  
  output_wires_ = 
    {GetRegister().template EmplaceWire<swift::MatrixWire<T>>(backend_, u, v, number_of_simd_values)};
    
  matrix_gamma_xy_my_id_ = CreateMatrices<T>(u, v, number_of_simd_values);
  matrix_gamma_xy_previous_id_ = CreateMatrices<T>(u, v, number_of_simd_values);
  matrix_lambda_wd_0_ = CreateMatrices<T>(u, v, number_of_simd_values);
  matrix_lambda_wd_1_ = CreateMatrices<T>(u, v, number_of_simd_values);
  matrix_lambda_wd_2_ = CreateMatrices<T>(u, v, number_of_simd_values);

  uint64_t my_id = GetCommunicationLayer().GetMyId();
  uint64_t previous_id = (my_id + 2) % 3;
  
  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  matrix_multiply_future_setup_ =
    message_manager.RegisterReceive(previous_id, kSwiftSetupMultiplyGate, gate_id_);
    
  if(my_id == 0) {
    matrix_multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftOnlineMultiplyGate, gate_id_);
  } else if(my_id == 1) {
    matrix_multiply_future_online_ = 
      message_manager.RegisterReceive(2, kSwiftOnlineMultiplyGate, gate_id_);
  } else if(my_id == 2) {
    matrix_multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftOnlineMultiplyGate, gate_id_);
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    //We are S_0, so we reserve hash memory for the hash we will receive from S2
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        u * v * number_of_simd_values * sizeof(T), 2);
    //we also reserve memory for the hash we will be sending to S1 and S2
    verifier_s1_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        u * v * number_of_simd_values * sizeof(T), 1);
    verifier_s2_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        u * v * number_of_simd_values * sizeof(T), 2);
  } else {
    //We are S1 or S2 and thus will receive a hash from S0;
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        u * v * number_of_simd_values * sizeof(T), 0);
  }
  if(my_id == 2) {
    //We reserve memory for the hash we will be sending to S0
    verifier_s2_message_data_ = 
      multipy_hash_verifier->ReserveHashMessage(
        u * v * number_of_simd_values * sizeof(T), 0);
  }
}

template<typename T>
void FpaMatrixMultiplicationGate<T>::EvaluateSetup() {
  using boost::numeric::ublas::matrix;
  using communication::MessageType::kSwiftSetupMultiplyGate;
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  auto matrix_out_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_a_[0]);
  assert(matrix_a_wire);
  auto matrix_b_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_b_[0]);
  assert(matrix_b_wire);
  
  auto& a_my_id_lambda_matrices = matrix_a_wire->GetMutableLambdaMyIdMatrices();
  auto& a_previous_id_lambda_matrices = matrix_a_wire->GetMutableLambdaPreviousIdMatrices();
  auto& b_my_id_lambda_matrices = matrix_b_wire->GetMutableLambdaMyIdMatrices();
  auto& b_previous_id_lambda_matrices = matrix_b_wire->GetMutableLambdaPreviousIdMatrices();
  auto& out_my_id_lambda_matrices = matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_previous_id_lambda_matrices = matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  
  size_t const number_of_simd_values = matrix_a_wire->GetNumberOfSimdValues();
  size_t const u = a_my_id_lambda_matrices[0].size1();
  size_t const w = a_my_id_lambda_matrices[0].size2();
  size_t const v = b_my_id_lambda_matrices[0].size2();
  size_t const u_v_elements = u * v * number_of_simd_values;
  size_t const number_of_gamma_xy_bytes = u_v_elements * sizeof(UInt128);
  size_t const random_bytes = number_of_gamma_xy_bytes;
  size_t const lambda_w_bytes = u * v * number_of_simd_values * sizeof(T);
    
  auto AssignToMatrix = [](auto& mat, uint8_t const* const data_pointer) {
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
  
  auto AssignFromMatrix = [](uint8_t* const data_pointer, auto const& mat) {
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
  
  //We assume the role of S_i and generate the random numbers we share with S_i+1
  auto& rng_i = backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
  //We assume the role of S_i+1 and generate the random numbers we share with S_i
  auto& rng_i_minus_1 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
  //randoms_my_id contains gamma_xy_my_id
  std::vector<uint8_t> randoms_my_id = 
    rng_i.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
  //randoms_previous_id contains gamma_xy_previous_id
  std::vector<uint8_t> randoms_previous_id = 
    rng_i_minus_1.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
  auto& rng_global = backend_.GetBaseProvider().GetGlobalRandomnessGenerator();
  
  std::vector<uint8_t> lambdas_w_0_2 = 
    rng_global.template GetUnsigned<uint8_t>(gate_id_, 2 * lambda_w_bytes);
  std::vector<uint8_t> lambdas_w_1;
  if(my_id == 1) {
    auto& rng_1_2 = backend_.GetBaseProvider().GetMyRandomnessGenerator(2);
    lambdas_w_1 = rng_1_2.template GetUnsigned<uint8_t>(gate_id_, lambda_w_bytes);
  } else if(my_id == 2) {
    auto& rng_1_2 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(1);
    lambdas_w_1 = rng_1_2.template GetUnsigned<uint8_t>(gate_id_, lambda_w_bytes);
  }
  
  backend_.GetSwiftTruncation()->GetRDoneCondition().Wait();
  backend_.GetSwiftTruncation()->GetRDDoneCondition().Wait();
  std::span<uint64_t const> rd_values_my_id = truncation_pairs_.GetRdsMyId();
  std::span<uint64_t const> rd_values_previous_id = truncation_pairs_.GetRdsPreviousId();
  {
    size_t offset = 0;
    uint8_t* lambda_w_0_pointer = lambdas_w_0_2.data();
    uint8_t* lambda_w_1_pointer = (my_id == 0) ? nullptr : lambdas_w_1.data();
    uint8_t* lambda_w_2_pointer = lambdas_w_0_2.data() + lambda_w_bytes;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          size_t const index = s * u * v + i * v + j;
          T lambda_w_0, lambda_w_1, lambda_w_2;
          memcpy(&lambda_w_0, lambda_w_0_pointer + offset, sizeof(T));
          memcpy(&lambda_w_2, lambda_w_2_pointer + offset, sizeof(T));
          matrix_lambda_wd_0_[s](i, j) = lambda_w_0;
          matrix_lambda_wd_2_[s](i, j) = lambda_w_2;
          if(my_id != 0) {
            memcpy(&lambda_w_1, lambda_w_1_pointer + offset, sizeof(T));
            matrix_lambda_wd_1_[s](i, j) = lambda_w_1;
          }
          switch(my_id) {
            case 0: {
              out_previous_id_lambda_matrices[s](i, j) =
                T(rd_values_previous_id[index]) + lambda_w_2;
              out_my_id_lambda_matrices[s](i, j) =
                T(rd_values_my_id[index]) + lambda_w_0;
              break;
            }
            case 1: {
              out_previous_id_lambda_matrices[s](i, j) =
                T(rd_values_previous_id[index]) + lambda_w_0;
              out_my_id_lambda_matrices[s](i, j) =
                T(rd_values_my_id[index]) + lambda_w_1;
              break;
            }
            case 2: {
              out_previous_id_lambda_matrices[s](i, j) =
                T(rd_values_previous_id[index]) + lambda_w_1;
              out_my_id_lambda_matrices[s](i, j) =
                T(rd_values_my_id[index]) + lambda_w_2;
              break;
            }
          }
          offset += sizeof(T);
        }
      }
    }
    assert(offset == u * v * number_of_simd_values * sizeof(T));
  }
  matrix_out_wire->SetSetupIsReady();
  
  //Extend input lambdas
  std::vector<matrix<UInt128>> extended_a_my_id_lambda_matrices;
  std::vector<matrix<UInt128>> extended_a_previous_id_lambda_matrices;
  std::vector<matrix<UInt128>> extended_b_my_id_lambda_matrices;
  std::vector<matrix<UInt128>> extended_b_previous_id_lambda_matrices;
  extended_a_my_id_lambda_matrices.reserve(number_of_simd_values);
  extended_a_previous_id_lambda_matrices.reserve(number_of_simd_values);
  extended_b_my_id_lambda_matrices.reserve(number_of_simd_values);
  extended_b_previous_id_lambda_matrices.reserve(number_of_simd_values);
  matrix_a_wire->GetSetupReadyCondition()->Wait();
  matrix_b_wire->GetSetupReadyCondition()->Wait();
  for(size_t s = 0; s != number_of_simd_values; ++s) {
    [[maybe_unused]] size_t const u_s = a_my_id_lambda_matrices[s].size1();
    [[maybe_unused]] size_t const w_s = a_my_id_lambda_matrices[s].size2();
    [[maybe_unused]] size_t const v_s = b_my_id_lambda_matrices[s].size2();
    
    assert(u_s == u);
    assert(w_s == w);
    assert(v_s == v);
    assert(a_my_id_lambda_matrices[s].size1() == u);
    assert(a_my_id_lambda_matrices[s].size2() == w);
    assert(b_my_id_lambda_matrices[s].size1() == w);
    assert(b_my_id_lambda_matrices[s].size2() == v);
    assert(out_my_id_lambda_matrices[s].size1() == u);
    assert(out_my_id_lambda_matrices[s].size2() == v);
    assert(a_previous_id_lambda_matrices[s].size1() == u);
    assert(a_previous_id_lambda_matrices[s].size2() == w);
    assert(b_previous_id_lambda_matrices[s].size1() == w);
    assert(b_previous_id_lambda_matrices[s].size2() == v);
    assert(out_previous_id_lambda_matrices[s].size1() == u);
    assert(out_previous_id_lambda_matrices[s].size2() == v);
    
    extended_a_my_id_lambda_matrices.emplace_back(u, w);
    extended_a_previous_id_lambda_matrices.emplace_back(u, w);
    extended_b_my_id_lambda_matrices.emplace_back(w, v);
    extended_b_previous_id_lambda_matrices.emplace_back(w, v);
    
    for(size_t i = 0; i != u; ++i) {
      for(size_t j = 0; j != w; ++j) {
        extended_a_my_id_lambda_matrices[s](i, j) =
          a_my_id_lambda_matrices[s](i, j);
        extended_a_previous_id_lambda_matrices[s](i, j) =
          a_previous_id_lambda_matrices[s](i, j);
      }
    }
    
    for(size_t i = 0; i != w; ++i) {
      for(size_t j = 0; j != v; ++j) {
        extended_b_my_id_lambda_matrices[s](i, j) =
          b_my_id_lambda_matrices[s](i, j);
        extended_b_previous_id_lambda_matrices[s](i, j) =
          b_previous_id_lambda_matrices[s](i, j);
      }
    }
  }
  
  {
    size_t offset = 0;
    uint8_t const* const alpha_i_pointer = randoms_my_id.data();
    uint8_t const* const alpha_i_minus_1_pointer = randoms_previous_id.data();
    uint8_t* const c_i_pointer = randoms_my_id.data();
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      matrix<UInt128> alpha_i(u, v), alpha_i_minus_1(u, v);
      AssignToMatrix(alpha_i, alpha_i_pointer + offset);
      AssignToMatrix(alpha_i_minus_1, alpha_i_minus_1_pointer + offset);
      matrix<UInt128> c_i = 
        prod(extended_a_my_id_lambda_matrices[s], extended_b_my_id_lambda_matrices[s]) +
        prod(extended_a_my_id_lambda_matrices[s], extended_b_previous_id_lambda_matrices[s]) +
        prod(extended_a_previous_id_lambda_matrices[s], extended_b_my_id_lambda_matrices[s]) +
        alpha_i - alpha_i_minus_1;
      AssignFromMatrix(c_i_pointer + offset, c_i);
      offset += u * v * sizeof(UInt128);
    }
    assert(offset == number_of_gamma_xy_bytes);
  }
  //Now the c_i values are in randoms_my_id[0,...,number_of_gamma_xy_bytes]
  
  {
    auto payload = std::span<uint8_t const>(randoms_my_id.data(), number_of_gamma_xy_bytes);
    auto message = communication::BuildMessage(kSwiftSetupMultiplyGate, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  
  {
    auto message = matrix_multiply_future_setup_.get();
    const auto payload = communication::GetMessage(message.data())->payload();
    auto received_data = std::span<uint8_t const>{payload->Data(), payload->size()};
    {
      size_t gamma_xy_offset = 0;
      uint8_t const* const gamma_xy_my_id_pointer = randoms_my_id.data();
      uint8_t const* const gamma_xy_previous_id_pointer = received_data.data();
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        matrix<UInt128> gamma_xy_my_id(u, v), gamma_xy_previous_id(u, v);
        AssignToMatrix(gamma_xy_my_id, 
                       gamma_xy_my_id_pointer + gamma_xy_offset);
        AssignToMatrix(gamma_xy_previous_id, 
                       gamma_xy_previous_id_pointer + gamma_xy_offset);
        triple_.AppendTriple(
          extended_a_my_id_lambda_matrices[s], 
          extended_a_previous_id_lambda_matrices[s],
          extended_b_my_id_lambda_matrices[s], 
          extended_b_previous_id_lambda_matrices[s],
          gamma_xy_my_id, 
          gamma_xy_previous_id);
        for(size_t i = 0; i != u; ++i) {
          for(size_t j = 0; j != v; ++j) {
            matrix_gamma_xy_my_id_[s](i, j) = 
              T(gamma_xy_my_id(i, j));
            matrix_gamma_xy_previous_id_[s](i, j) = 
              T(gamma_xy_previous_id(i, j));
          }
        }
        gamma_xy_offset += u * v * sizeof(UInt128);
      }
      backend_.GetSwiftVerifier()->SetReady();
      assert(gamma_xy_offset == number_of_gamma_xy_bytes);
    }
  }
}

template<typename T>
void FpaMatrixMultiplicationGate<T>::EvaluateOnline() {
  using communication::MessageType::kSwiftOnlineMultiplyGate;
  using boost::numeric::ublas::matrix;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_a_[0]);
  assert(matrix_a_wire);
  auto matrix_b_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_b_[0]);
  assert(matrix_b_wire);
  size_t number_of_simd_values = matrix_a_wire->GetNumberOfSimdValues();
  assert(matrix_b_wire->GetNumberOfSimdValues() == number_of_simd_values);
  assert(matrix_out_wire->GetNumberOfSimdValues() == number_of_simd_values);
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
  
  auto& a_value_matrices = matrix_a_wire->GetMutableValueMatrices();
  auto& a_my_id_lambda_matrices = matrix_a_wire->GetMutableLambdaMyIdMatrices();
  auto& a_previous_id_lambda_matrices = matrix_a_wire->GetMutableLambdaPreviousIdMatrices();
  auto& b_value_matrices = matrix_b_wire->GetMutableValueMatrices();
  auto& b_my_id_lambda_matrices = matrix_b_wire->GetMutableLambdaMyIdMatrices();
  auto& b_previous_id_lambda_matrices = matrix_b_wire->GetMutableLambdaPreviousIdMatrices();
  auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
  
  size_t const u = a_my_id_lambda_matrices[0].size1();
  size_t const v = b_my_id_lambda_matrices[0].size2();
  
  std::vector<matrix<T>> m_my_id, m_previous_id;
  m_my_id.reserve(number_of_simd_values);
  m_previous_id.reserve(number_of_simd_values);
  
  std::span<uint64_t const> r_values_my_id = truncation_pairs_.GetRsMyId();
  std::span<uint64_t const> r_values_previous_id = truncation_pairs_.GetRsPreviousId();
  for(size_t s = 0; s != number_of_simd_values; ++s) {
    matrix<T> matrix_r_my_id(u, v), matrix_r_previous_id(u, v);
    for(size_t i = 0; i != u; ++i) {
      for(size_t j = 0; j != v; ++j) {
        size_t const index = s * u * v + i * v + j;
        matrix_r_my_id(i, j) = T(r_values_my_id[index]);
        matrix_r_previous_id(i, j) = T(r_values_previous_id[index]);
      }
    }
    m_my_id.emplace_back(
      prod(a_value_matrices[s], b_my_id_lambda_matrices[s])
      + prod(a_my_id_lambda_matrices[s], b_value_matrices[s])
      + matrix_gamma_xy_my_id_[s] - matrix_r_my_id);
    m_previous_id.emplace_back( 
      prod(a_value_matrices[s], b_previous_id_lambda_matrices[s])
      + prod(a_previous_id_lambda_matrices[s], b_value_matrices[s])
      + matrix_gamma_xy_previous_id_[s] - matrix_r_previous_id);
  }
  //m_my_id and m_previous_id contain W_i
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    verifier_s1_message_data_.AssignData(m_previous_id);
    multipy_hash_verifier->SetReady();
    verifier_s2_message_data_.AssignData(m_my_id);
    multipy_hash_verifier->SetReady();
  }
  else if(my_id == 1) {
    //We are S1 so we send W_0 to S2, which is m_previous_id
    {
      auto payload = SerializeMatrices(m_previous_id);
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
    }
  } else if(my_id == 2) {
    //We are S2 so we send W_2 to S1, which is m_my_id
    {
      auto payload = SerializeMatrices(m_my_id);
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(1, message.Release());
    }
  } else {
    assert(false);
  }
  {
    auto message = matrix_multiply_future_online_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    std::vector<matrix<T>> m_missing_id = 
      CreateMatrices<T>(u, v, number_of_simd_values);
    DeserializeMatrices(
      m_missing_id, std::span<uint8_t const>{payload->Data(), payload->size()});
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      //Compute [[Wd]]
      out_value_matrices[s] = 
        m_previous_id[s] + m_my_id[s] + m_missing_id[s]
        + prod(a_value_matrices[s], b_value_matrices[s])
        - matrix_lambda_wd_0_[s] - matrix_lambda_wd_1_[s]
        - matrix_lambda_wd_2_[s];
    }
    if(my_id == 1) {
      auto payload = SerializeMatrices(out_value_matrices);
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(0, message.Release());
    } else if(my_id == 2) {
      verifier_s2_message_data_.AssignData(m_previous_id);
      multipy_hash_verifier->SetReady();
    }
    verifier_received_hash_data_.AssignData(m_missing_id);
    multipy_hash_verifier->SetReady();
    //lambdas Z has already been calculated in the setup phase
  }
}

template class FpaMatrixMultiplicationGate<std::uint8_t>;
template class FpaMatrixMultiplicationGate<std::uint16_t>;
template class FpaMatrixMultiplicationGate<std::uint32_t>;
template class FpaMatrixMultiplicationGate<std::uint64_t>;

constexpr bool checkSignedShift() {
  uint64_t unsigned_number = -2;
  int64_t signed_number = unsigned_number;
  return (signed_number >> 1) == -1;
}

static_assert(checkSignedShift(), "Signed shift is not supported on this platform");

template<typename T>
void Truncate(std::vector<boost::numeric::ublas::matrix<T>>& m, unsigned precision) {
  for(size_t k = 0; k != m.size(); ++k)
  for(size_t i = 0; i != m[k].size1(); ++i) {
    for(size_t j = 0; j != m[k].size2(); ++j) {
      T& element = m[k](i, j);
      std::make_signed_t<T> signed_element = element;
      signed_element >>= precision;
      element = signed_element;
    }
  }
}

template<typename T>
SociumFpaMatrixMultiplicationGate<T>::SociumFpaMatrixMultiplicationGate(
  swift::MatrixWirePointer<T> matrix_a, swift::MatrixWirePointer<T> matrix_b, unsigned precision)
: TwoGate(matrix_a->GetBackend()),
  triple_(backend_.GetSociumVerifier()->ReserveMatrixTriples128(matrix_a->GetNumberOfSimdValues())), precision_(precision) {
  using communication::MessageType::kSociumSetupMultiplyGate;
  using communication::MessageType::kSociumOnlineMultiplyGate;
  size_t const u = matrix_a->GetMutableLambdaMyIdMatrices()[0].size1();
  size_t const v = matrix_b->GetMutableLambdaMyIdMatrices()[0].size2();
  size_t const number_of_simd_values = matrix_a->GetNumberOfSimdValues();
  assert(matrix_a->GetMutableLambdaMyIdMatrices()[0].size2() == matrix_b->GetMutableLambdaMyIdMatrices()[0].size1());
  assert(matrix_a->GetMutableLambdaPreviousIdMatrices()[0].size2() == matrix_b->GetMutableLambdaPreviousIdMatrices()[0].size1());
  assert(matrix_b->GetNumberOfSimdValues() == number_of_simd_values);
  
  parent_a_ = {std::move(matrix_a)};
  parent_b_ = {std::move(matrix_b)};
  
  output_wires_ = 
    {GetRegister().template EmplaceWire<swift::MatrixWire<T>>(backend_, u, v, number_of_simd_values)};
    
  uint64_t my_id = GetCommunicationLayer().GetMyId();
  uint64_t previous_id = (my_id + 2) % 3;

  matrix_gamma_xy_my_id_ = CreateMatrices<T>(u, v, number_of_simd_values);
  if (my_id == 0 || my_id == 1) { // S2 will never receive gamma1
    matrix_gamma_xy_previous_id_ = CreateMatrices<T>(u, v, number_of_simd_values);
  }

  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  if (my_id == 0 || my_id == 1) { // S2 will never receive gamma1
    matrix_multiply_future_setup_ =
      message_manager.RegisterReceive(previous_id, kSociumSetupMultiplyGate, gate_id_);
  }
    
  if(my_id == 0) {
    matrix_multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSociumOnlineMultiplyGate, gate_id_);
  } else if(my_id == 1) {
    matrix_multiply_future_online_ = 
      message_manager.RegisterReceive(2, kSociumOnlineMultiplyGate, gate_id_);
  } else if(my_id == 2) {
    matrix_multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSociumOnlineMultiplyGate, gate_id_);
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    //we reserve memory for the hash we will be sending to S1
    verifier_s1_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        u * v * number_of_simd_values * sizeof(T), 1);
  } else if (my_id == 1) {
    //We are S1 and thus will receive a hash from S0;
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        u * v * number_of_simd_values * sizeof(T), 0);
  }
}

template<typename T>
void SociumFpaMatrixMultiplicationGate<T>::EvaluateSetup() {
  using boost::numeric::ublas::matrix;
  using communication::MessageType::kSociumSetupMultiplyGate;
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  auto matrix_out_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_a_[0]);
  assert(matrix_a_wire);
  auto matrix_b_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_b_[0]);
  assert(matrix_b_wire);
  
  auto& a_my_id_lambda_matrices = matrix_a_wire->GetMutableLambdaMyIdMatrices();
  auto& a_previous_id_lambda_matrices = matrix_a_wire->GetMutableLambdaPreviousIdMatrices();
  auto& b_my_id_lambda_matrices = matrix_b_wire->GetMutableLambdaMyIdMatrices();
  auto& b_previous_id_lambda_matrices = matrix_b_wire->GetMutableLambdaPreviousIdMatrices();
  auto& out_my_id_lambda_matrices = matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_previous_id_lambda_matrices = matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  
  size_t const number_of_simd_values = matrix_a_wire->GetNumberOfSimdValues();
  size_t const u = a_my_id_lambda_matrices[0].size1();
  size_t const w = a_my_id_lambda_matrices[0].size2();
  size_t const v = b_my_id_lambda_matrices[0].size2();
  size_t const u_v_elements = u * v * number_of_simd_values;
  size_t const number_of_gamma_xy_bytes = u_v_elements * sizeof(UInt128);
  size_t const number_of_lambda_z_bytes = u_v_elements * sizeof(T);
  size_t const random_bytes = number_of_gamma_xy_bytes + number_of_lambda_z_bytes;
    
  auto AssignToMatrix = [](auto& mat, uint8_t const* const data_pointer) {
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
  
  auto AssignFromMatrix = [](uint8_t* const data_pointer, auto const& mat) {
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

  //We assume the role of S_i and generate the random numbers we share with S_i+1
  auto& rng_i = backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
  //We assume the role of S_i+1 and generate the random numbers we share with S_i
  auto& rng_i_minus_1 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
  //randoms_my_id contains gamma_xy_my_id
  std::vector<uint8_t> randoms_my_id = 
    rng_i.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
  //randoms_previous_id contains gamma_xy_previous_id
  std::vector<uint8_t> randoms_previous_id = 
    rng_i_minus_1.template GetUnsigned<uint8_t>(gate_id_, random_bytes);

  {
    size_t lambda_z_offset = 0;
    uint8_t const* const lambda_z_my_id_pointer = 
      randoms_my_id.data() + number_of_gamma_xy_bytes;
    uint8_t const* const lambda_z_previous_id_pointer = 
      randoms_previous_id.data() + number_of_gamma_xy_bytes;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      AssignToMatrix(out_my_id_lambda_matrices[s], 
                     lambda_z_my_id_pointer + lambda_z_offset);
      AssignToMatrix(out_previous_id_lambda_matrices[s], 
                     lambda_z_previous_id_pointer + lambda_z_offset);
      lambda_z_offset += u * v * sizeof(T);
    }
    assert(lambda_z_offset == number_of_lambda_z_bytes);
  }
  matrix_out_wire->SetSetupIsReady();
    
  //Extend input lambdas
  std::vector<matrix<UInt128>> extended_a_my_id_lambda_matrices;
  std::vector<matrix<UInt128>> extended_a_previous_id_lambda_matrices;
  std::vector<matrix<UInt128>> extended_b_my_id_lambda_matrices;
  std::vector<matrix<UInt128>> extended_b_previous_id_lambda_matrices;
  extended_a_my_id_lambda_matrices.reserve(number_of_simd_values);
  extended_a_previous_id_lambda_matrices.reserve(number_of_simd_values);
  extended_b_my_id_lambda_matrices.reserve(number_of_simd_values);
  extended_b_previous_id_lambda_matrices.reserve(number_of_simd_values);
  matrix_a_wire->GetSetupReadyCondition()->Wait();
  matrix_b_wire->GetSetupReadyCondition()->Wait();
  for(size_t s = 0; s != number_of_simd_values; ++s) {
    [[maybe_unused]] size_t const u_s = a_my_id_lambda_matrices[s].size1();
    [[maybe_unused]] size_t const w_s = a_my_id_lambda_matrices[s].size2();
    [[maybe_unused]] size_t const v_s = b_my_id_lambda_matrices[s].size2();
    
    assert(u_s == u);
    assert(w_s == w);
    assert(v_s == v);
    assert(a_my_id_lambda_matrices[s].size1() == u);
    assert(a_my_id_lambda_matrices[s].size2() == w);
    assert(b_my_id_lambda_matrices[s].size1() == w);
    assert(b_my_id_lambda_matrices[s].size2() == v);
    assert(out_my_id_lambda_matrices[s].size1() == u);
    assert(out_my_id_lambda_matrices[s].size2() == v);
    assert(a_previous_id_lambda_matrices[s].size1() == u);
    assert(a_previous_id_lambda_matrices[s].size2() == w);
    assert(b_previous_id_lambda_matrices[s].size1() == w);
    assert(b_previous_id_lambda_matrices[s].size2() == v);
    assert(out_previous_id_lambda_matrices[s].size1() == u);
    assert(out_previous_id_lambda_matrices[s].size2() == v);
    
    extended_a_my_id_lambda_matrices.emplace_back(u, w);
    extended_a_previous_id_lambda_matrices.emplace_back(u, w);
    extended_b_my_id_lambda_matrices.emplace_back(w, v);
    extended_b_previous_id_lambda_matrices.emplace_back(w, v);
    
    for(size_t i = 0; i != u; ++i) {
      for(size_t j = 0; j != w; ++j) {
        extended_a_my_id_lambda_matrices[s](i, j) =
          a_my_id_lambda_matrices[s](i, j);
        extended_a_previous_id_lambda_matrices[s](i, j) =
          a_previous_id_lambda_matrices[s](i, j);
      }
    }
    
    for(size_t i = 0; i != w; ++i) {
      for(size_t j = 0; j != v; ++j) {
        extended_b_my_id_lambda_matrices[s](i, j) =
          b_my_id_lambda_matrices[s](i, j);
        extended_b_previous_id_lambda_matrices[s](i, j) =
          b_previous_id_lambda_matrices[s](i, j);
      }
    }
  }
  
  {
    size_t offset = 0;
    uint8_t const* const alpha_i_pointer = randoms_my_id.data();
    uint8_t const* const alpha_i_minus_1_pointer = randoms_previous_id.data();
    uint8_t* const c_i_pointer = randoms_my_id.data();
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      matrix<UInt128> alpha_i(u, v), alpha_i_minus_1(u, v);
      AssignToMatrix(alpha_i, alpha_i_pointer + offset);
      AssignToMatrix(alpha_i_minus_1, alpha_i_minus_1_pointer + offset);
      matrix<UInt128> c_i = 
        prod(extended_a_my_id_lambda_matrices[s], extended_b_my_id_lambda_matrices[s]) +
        prod(extended_a_my_id_lambda_matrices[s], extended_b_previous_id_lambda_matrices[s]) +
        prod(extended_a_previous_id_lambda_matrices[s], extended_b_my_id_lambda_matrices[s]) +
        alpha_i - alpha_i_minus_1;
      AssignFromMatrix(c_i_pointer + offset, c_i);
      offset += u * v * sizeof(UInt128);
    }
    assert(offset == number_of_gamma_xy_bytes);
  }
  //Now the c_i values are in randoms_my_id[0,...,number_of_gamma_xy_bytes]
  
  if (my_id == 0 || my_id == 2) { // S_1 does not send in SOCIUM
    auto payload = std::span<uint8_t const>(randoms_my_id.data(), number_of_gamma_xy_bytes);
    auto message = communication::BuildMessage(kSociumSetupMultiplyGate, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  
  if (my_id == 0 || my_id == 1) { // S2 does not receive in SOCIUM
    auto message = matrix_multiply_future_setup_.get();
    const auto payload = communication::GetMessage(message.data())->payload();
    auto received_data = std::span<uint8_t const>{payload->Data(), payload->size()};
    {
      size_t gamma_xy_offset = 0;
      uint8_t const* const gamma_xy_my_id_pointer = randoms_my_id.data();
      uint8_t const* const gamma_xy_previous_id_pointer = received_data.data();
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        matrix<UInt128> gamma_xy_my_id(u, v), gamma_xy_previous_id(u, v);
        AssignToMatrix(gamma_xy_my_id, 
                       gamma_xy_my_id_pointer + gamma_xy_offset);
        AssignToMatrix(gamma_xy_previous_id, 
                       gamma_xy_previous_id_pointer + gamma_xy_offset);

        triple_.AppendTriple(
          extended_a_my_id_lambda_matrices[s], 
          extended_a_previous_id_lambda_matrices[s],
          extended_b_my_id_lambda_matrices[s], 
          extended_b_previous_id_lambda_matrices[s],
          gamma_xy_my_id, 
          gamma_xy_previous_id);
        for(size_t i = 0; i != u; ++i) {
          for(size_t j = 0; j != v; ++j) {
            matrix_gamma_xy_my_id_[s](i, j) = 
              T(gamma_xy_my_id(i, j));
            matrix_gamma_xy_previous_id_[s](i, j) = 
              T(gamma_xy_previous_id(i, j));
          }
        }
        gamma_xy_offset += u * v * sizeof(UInt128);
      }
      backend_.GetSociumVerifier()->SetReady();

      assert(gamma_xy_offset == number_of_gamma_xy_bytes);
    }
  } else { // S2
    matrix<UInt128> empty(u, v);
    size_t gamma_xy_offset = 0;
    uint8_t const* const gamma_xy_my_id_pointer = randoms_my_id.data();
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      matrix<UInt128> gamma_xy_my_id(u, v);
      AssignToMatrix(gamma_xy_my_id, 
                     gamma_xy_my_id_pointer + gamma_xy_offset);

      triple_.AppendTriple(
        extended_a_my_id_lambda_matrices[s], 
        extended_a_previous_id_lambda_matrices[s],
        extended_b_my_id_lambda_matrices[s], 
        extended_b_previous_id_lambda_matrices[s],
        gamma_xy_my_id, 
        empty);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          matrix_gamma_xy_my_id_[s](i, j) = 
            T(gamma_xy_my_id(i, j));
        }
      }
      gamma_xy_offset += u * v * sizeof(UInt128);
    }
    backend_.GetSociumVerifier()->SetReady();

    assert(gamma_xy_offset == number_of_gamma_xy_bytes);
  }
}

template<typename T>
void SociumFpaMatrixMultiplicationGate<T>::EvaluateOnline() {
  using communication::MessageType::kSociumOnlineMultiplyGate;
  using boost::numeric::ublas::matrix;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_a_[0]);
  assert(matrix_a_wire);
  auto matrix_b_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_b_[0]);
  assert(matrix_b_wire);
  size_t number_of_simd_values = matrix_a_wire->GetNumberOfSimdValues();
  assert(matrix_b_wire->GetNumberOfSimdValues() == number_of_simd_values);
  assert(matrix_out_wire->GetNumberOfSimdValues() == number_of_simd_values);
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
  
  auto& a_value_matrices = matrix_a_wire->GetMutableValueMatrices();
  auto& a_my_id_lambda_matrices = matrix_a_wire->GetMutableLambdaMyIdMatrices();
  auto& a_previous_id_lambda_matrices = matrix_a_wire->GetMutableLambdaPreviousIdMatrices();
  auto& b_value_matrices = matrix_b_wire->GetMutableValueMatrices();
  auto& b_my_id_lambda_matrices = matrix_b_wire->GetMutableLambdaMyIdMatrices();
  auto& b_previous_id_lambda_matrices = matrix_b_wire->GetMutableLambdaPreviousIdMatrices();
  auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
  auto& out_my_id_lambda_matrices = matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_previous_id_lambda_matrices = matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  
  size_t const u = a_my_id_lambda_matrices[0].size1();
  size_t const v = b_my_id_lambda_matrices[0].size2();
  
  std::vector<matrix<T>> t_my_id;
  t_my_id.reserve(number_of_simd_values);
  
  for(size_t s = 0; s != number_of_simd_values; ++s) {
    if (my_id == 1) {
      t_my_id.emplace_back(
        prod(a_value_matrices[s], b_previous_id_lambda_matrices[s])
        + prod(a_previous_id_lambda_matrices[s], b_value_matrices[s])
        + matrix_gamma_xy_previous_id_[s]
        + prod(a_value_matrices[s], b_my_id_lambda_matrices[s])
        + prod(a_my_id_lambda_matrices[s], b_value_matrices[s])
        + matrix_gamma_xy_my_id_[s]
      );
      Truncate(t_my_id, precision_);
      t_my_id[s] = t_my_id[s] - out_previous_id_lambda_matrices[s] - out_my_id_lambda_matrices[s];
    } else if (my_id == 0) {
      t_my_id.emplace_back(
        prod(a_value_matrices[s], b_value_matrices[s])
        + prod(a_value_matrices[s], b_previous_id_lambda_matrices[s])
        + prod(a_previous_id_lambda_matrices[s], b_value_matrices[s])
        + matrix_gamma_xy_previous_id_[s]
      );
      Truncate(t_my_id, precision_);
      t_my_id[s] = t_my_id[s] - out_previous_id_lambda_matrices[s];
    } else {
      t_my_id.emplace_back(
        prod(a_value_matrices[s], b_value_matrices[s])
        + prod(a_value_matrices[s], b_my_id_lambda_matrices[s])
        + prod(a_my_id_lambda_matrices[s], b_value_matrices[s])
        + matrix_gamma_xy_my_id_[s]
      );
      Truncate(t_my_id, precision_);
      t_my_id[s] = t_my_id[s] - out_my_id_lambda_matrices[s];
    }
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier(); // Swift Verifier has the required functionality also for Socium
  if(my_id == 0) {
    verifier_s1_message_data_.AssignData(t_my_id);
    multipy_hash_verifier->SetReady();
  }
  else if(my_id == 1) {
    //We are S1 so we send T1 to S2, S0
    {
      auto payload = SerializeMatrices(t_my_id);
      auto message = 
        communication::BuildMessage(kSociumOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
    }
    
    {
      auto payload = SerializeMatrices(t_my_id);
      auto message = 
        communication::BuildMessage(kSociumOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(0, message.Release());
    }
  } else if(my_id == 2) {
    //We are S2 so we send T2 to S1
    {
      auto payload = SerializeMatrices(t_my_id);
      auto message = 
        communication::BuildMessage(kSociumOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(1, message.Release());
    }
  } else {
    assert(false);
  }

  {
    auto message = matrix_multiply_future_online_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    std::vector<matrix<T>> t_missing_id = 
      CreateMatrices<T>(u, v, number_of_simd_values);
    DeserializeMatrices(
      t_missing_id, std::span<uint8_t const>{payload->Data(), payload->size()});
    if (my_id == 1) {
      verifier_received_hash_data_.AssignData(t_missing_id);
      multipy_hash_verifier->SetReady();
    }
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      out_value_matrices[s] = 
        t_my_id[s] + t_missing_id[s];
    }
  }
}

template class SociumFpaMatrixMultiplicationGate<std::uint8_t>;
template class SociumFpaMatrixMultiplicationGate<std::uint16_t>;
template class SociumFpaMatrixMultiplicationGate<std::uint32_t>;
template class SociumFpaMatrixMultiplicationGate<std::uint64_t>;


template<typename T>
FpaMatrixMultiplicationConstantGate<T>::FpaMatrixMultiplicationConstantGate(
  swift::MatrixWirePointer<T> matrix_a, size_t constant)
: OneGate(matrix_a->GetBackend()),
  constant_(constant),
  truncation_pairs_(backend_.GetSwiftTruncation()->AddTruncationPairs(
    matrix_a->GetNumberOfSimdValues()
    * matrix_a->GetMutableLambdaMyIdMatrices()[0].size1()
    * matrix_a->GetMutableLambdaMyIdMatrices()[0].size2())) {
  using communication::MessageType::kSwiftOnlineMultiplyGate;
  size_t const u = matrix_a->GetMutableLambdaMyIdMatrices()[0].size1();
  size_t const v = matrix_a->GetMutableLambdaMyIdMatrices()[0].size2();
  size_t const number_of_simd_values = matrix_a->GetNumberOfSimdValues();
  
  parent_ = {std::move(matrix_a)};
  
  output_wires_ = 
    {GetRegister().template EmplaceWire<swift::MatrixWire<T>>(backend_, u, v, number_of_simd_values)};

  uint64_t my_id = GetCommunicationLayer().GetMyId();
  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  if(my_id == 0) {
    matrix_multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftOnlineMultiplyGate, gate_id_);
  } else if(my_id == 1) {
    matrix_multiply_future_online_ = 
      message_manager.RegisterReceive(2, kSwiftOnlineMultiplyGate, gate_id_);
  } else if(my_id == 2) {
    matrix_multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftOnlineMultiplyGate, gate_id_);
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    //We are S_0, so we reserve hash memory for the hash we will receive from S2
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        u * v * number_of_simd_values * sizeof(T), 2);
    //we also reserve memory for the hash we will be sending to S1 and S2
    verifier_s1_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        u * v * number_of_simd_values * sizeof(T), 1);
    verifier_s2_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        u * v * number_of_simd_values * sizeof(T), 2);
  } else {
    //We are S1 or S2 and thus will receive a hash from S0;
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        u * v * number_of_simd_values * sizeof(T), 0);
  }
  if(my_id == 2) {
    //We reserve memory for the hash we will be sending to S0
    verifier_s2_message_data_ = 
      multipy_hash_verifier->ReserveHashMessage(
        u * v * number_of_simd_values * sizeof(T), 0);
  }
}

template<typename T>
void FpaMatrixMultiplicationConstantGate<T>::EvaluateSetup() {
  using boost::numeric::ublas::matrix;
  auto matrix_out_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_[0]);
  assert(matrix_a_wire);
  
  auto& a_my_id_lambda_matrices =
    matrix_a_wire->GetMutableLambdaMyIdMatrices();
  auto& a_previous_id_lambda_matrices =
    matrix_a_wire->GetMutableLambdaPreviousIdMatrices();
  auto& out_my_id_lambda_matrices =
    matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_previous_id_lambda_matrices =
    matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  
  size_t const number_of_simd_values = matrix_a_wire->GetNumberOfSimdValues();
  size_t const u = a_my_id_lambda_matrices[0].size1();
  size_t const v = a_my_id_lambda_matrices[0].size2();

  matrix_a_wire->GetSetupReadyCondition()->Wait();
  backend_.GetSwiftTruncation()->GetRDoneCondition().Wait();
  backend_.GetSwiftTruncation()->GetRDDoneCondition().Wait();
  
  std::span<uint64_t const> r_values_my_id = truncation_pairs_.GetRsMyId();
  std::span<uint64_t const> r_values_previous_id = truncation_pairs_.GetRsPreviousId();
  for(size_t s = 0; s != number_of_simd_values; ++s) {
    matrix<T> matrix_r_my_id(u, v), matrix_r_previous_id(u, v);
    for(size_t i = 0; i != u; ++i) {
      for(size_t j = 0; j != v; ++j) {
        size_t const index = s * u * v + i * v + j;
        matrix_r_my_id(i, j) = T(r_values_my_id[index]);
        matrix_r_previous_id(i, j) = T(r_values_previous_id[index]);
      }
    }
    out_previous_id_lambda_matrices[s] = 
      constant_ * a_previous_id_lambda_matrices[s] - matrix_r_my_id;
    out_my_id_lambda_matrices[s] = 
      constant_ * a_my_id_lambda_matrices[s] - matrix_r_previous_id;
  }
  
  matrix_out_wire->SetSetupIsReady();
}

template<typename T>
void FpaMatrixMultiplicationConstantGate<T>::EvaluateOnline() {
  using communication::MessageType::kSwiftOnlineMultiplyGate;
  using boost::numeric::ublas::matrix;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = 
    std::dynamic_pointer_cast<swift::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire =
    std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_[0]);
  assert(matrix_a_wire);
  size_t const number_of_simd_values = 
    matrix_a_wire->GetNumberOfSimdValues();
  assert(matrix_out_wire->GetNumberOfSimdValues() == number_of_simd_values);
  WaitSetup();
  assert(setup_is_ready_);
  parent_[0]->GetIsReadyCondition().Wait();
  
  auto& a_value_matrices =
    matrix_a_wire->GetMutableValueMatrices();
  auto& out_value_matrices =
    matrix_out_wire->GetMutableValueMatrices();
  auto& out_my_id_lambda_matrices =
    matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_previous_id_lambda_matrices =
    matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  
  size_t const u = a_value_matrices[0].size1();
  size_t const v = a_value_matrices[0].size2();
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    verifier_s1_message_data_.AssignData(out_previous_id_lambda_matrices);
    multipy_hash_verifier->SetReady();
    verifier_s2_message_data_.AssignData(out_my_id_lambda_matrices);
    multipy_hash_verifier->SetReady();
  }
  else if(my_id == 1) {
    //We are S1 so we send lambda_y0 to S2
    {
      auto payload = SerializeMatrices(out_previous_id_lambda_matrices);
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
    }
  } else if(my_id == 2) {
    //We are S2 so we send lambda_y2 to S1
    {
      auto payload = SerializeMatrices(out_my_id_lambda_matrices);
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(1, message.Release());
    }
  } else {
    assert(false);
  }
  
  {
    auto message = matrix_multiply_future_online_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    std::vector<matrix<T>> lambda_missing_id = 
      CreateMatrices<T>(u, v, number_of_simd_values);
    DeserializeMatrices(
      lambda_missing_id, 
      std::span<uint8_t const>{payload->Data(), payload->size()});
    
    std::span<uint64_t const> rd_values_my_id = truncation_pairs_.GetRdsMyId();
    std::span<uint64_t const> rd_values_previous_id = truncation_pairs_.GetRdsPreviousId();
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      out_value_matrices[s] =
        constant_* a_value_matrices[s]
        + out_previous_id_lambda_matrices[s]
        + out_my_id_lambda_matrices[s]
        + lambda_missing_id[s];
      
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          size_t const index = s * u * v + i * v + j;
          out_my_id_lambda_matrices[s](i, j) +=
            T(rd_values_my_id[index]);
          out_previous_id_lambda_matrices[s](i, j) +=
            T(rd_values_previous_id[index]);
        }
      }
    }
    if(my_id == 1) {
      auto payload = SerializeMatrices(out_my_id_lambda_matrices);
      auto message = 
        communication::BuildMessage(kSwiftOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(0, message.Release());
    } else if(my_id == 2) {
      verifier_s2_message_data_.AssignData(out_previous_id_lambda_matrices);
      multipy_hash_verifier->SetReady();
    }
    verifier_received_hash_data_.AssignData(lambda_missing_id);
    multipy_hash_verifier->SetReady();
  }
}

template class FpaMatrixMultiplicationConstantGate<std::uint8_t>;
template class FpaMatrixMultiplicationConstantGate<std::uint16_t>;
template class FpaMatrixMultiplicationConstantGate<std::uint32_t>;
template class FpaMatrixMultiplicationConstantGate<std::uint64_t>;

template<typename T>
SociumFpaMatrixMultiplicationConstantGate<T>::SociumFpaMatrixMultiplicationConstantGate(
  swift::MatrixWirePointer<T> matrix_a, size_t constant, unsigned precision)
: OneGate(matrix_a->GetBackend()),
  constant_(constant), precision_(precision) {
  using communication::MessageType::kSociumSetupMultiplyGate;
  using communication::MessageType::kSociumOnlineMultiplyGate;
  size_t const u = matrix_a->GetMutableLambdaMyIdMatrices()[0].size1();
  size_t const v = matrix_a->GetMutableLambdaMyIdMatrices()[0].size2();
  size_t const number_of_simd_values = matrix_a->GetNumberOfSimdValues();
  
  parent_ = {std::move(matrix_a)};
  
  output_wires_ = 
    {GetRegister().template EmplaceWire<swift::MatrixWire<T>>(backend_, u, v, number_of_simd_values)};

  uint64_t my_id = GetCommunicationLayer().GetMyId();
  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  if(my_id == 0) {
    matrix_multiply_future_online_ = 
      message_manager.RegisterReceive(1, kSociumOnlineMultiplyGate, gate_id_);
  } else if(my_id == 1) {
    matrix_multiply_future_setup_ = 
      message_manager.RegisterReceive(0, kSociumSetupMultiplyGate, gate_id_);
  } else if(my_id == 2) {
    matrix_multiply_future_setup_ = 
      message_manager.RegisterReceive(0, kSociumSetupMultiplyGate, gate_id_);
  }
}

template<typename T>
void SociumFpaMatrixMultiplicationConstantGate<T>::EvaluateSetup() {
  using boost::numeric::ublas::matrix;
  using communication::MessageType::kSociumSetupMultiplyGate;
  auto matrix_out_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_[0]);
  assert(matrix_a_wire);
  
  auto& a_my_id_lambda_matrices =
    matrix_a_wire->GetMutableLambdaMyIdMatrices();
  auto& a_previous_id_lambda_matrices =
    matrix_a_wire->GetMutableLambdaPreviousIdMatrices();
  auto& out_my_id_lambda_matrices =
    matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_previous_id_lambda_matrices =
    matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  auto& out_value_matrices =
    matrix_out_wire->GetMutableValueMatrices();

  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  
  size_t const number_of_simd_values = matrix_a_wire->GetNumberOfSimdValues();
  size_t const u = a_my_id_lambda_matrices[0].size1();
  size_t const v = a_my_id_lambda_matrices[0].size2();
  size_t const u_v_elements = u * v * number_of_simd_values;
  size_t const number_of_lambda_z_bytes = u_v_elements * sizeof(T);
  size_t const random_bytes = number_of_lambda_z_bytes;

  auto AssignToMatrix = [](auto& mat, uint8_t const* const data_pointer) {
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

  //We assume the role of S_i and generate the random numbers we share with S_i+1
  auto& rng_i = backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
  //We assume the role of S_i+1 and generate the random numbers we share with S_i
  auto& rng_i_minus_1 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
  std::vector<uint8_t> randoms_my_id = 
    rng_i.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
  std::vector<uint8_t> randoms_previous_id = 
    rng_i_minus_1.template GetUnsigned<uint8_t>(gate_id_, random_bytes);

  // Sample output mask
  {
    size_t lambda_z_offset = 0;
    uint8_t const* const lambda_z_my_id_pointer = 
      randoms_my_id.data();
    uint8_t const* const lambda_z_previous_id_pointer = 
      randoms_previous_id.data();
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      AssignToMatrix(out_my_id_lambda_matrices[s], 
                     lambda_z_my_id_pointer + lambda_z_offset);
      AssignToMatrix(out_previous_id_lambda_matrices[s], 
                     lambda_z_previous_id_pointer + lambda_z_offset);
      lambda_z_offset += u * v * sizeof(T);
    }
    assert(lambda_z_offset == number_of_lambda_z_bytes);
  }
  matrix_out_wire->SetSetupIsReady();

  if (my_id == 0) {
    matrix_a_wire->GetSetupReadyCondition()->Wait();
    std::vector<matrix<T>> t0, t2;
    t0.reserve(number_of_simd_values);
    t2.reserve(number_of_simd_values);
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      t0.emplace_back(u, v);
      t0[s] = constant_ * (a_my_id_lambda_matrices[s] + a_previous_id_lambda_matrices[s]);
    }
    Truncate(t0, precision_);
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      t2.emplace_back(u, v);
      t2[s] = t0[s] - out_previous_id_lambda_matrices[s];
      out_value_matrices[s] = t2[s];
      t0[s] = t0[s] - out_my_id_lambda_matrices[s];
    }
    auto payload = SerializeMatrices(t0);
    auto message = 
      communication::BuildMessage(kSociumSetupMultiplyGate, gate_id_, payload);
    communication_layer.SendMessage(2, message.Release());
    auto payload2 = SerializeMatrices(t2);
    auto message2 = 
      communication::BuildMessage(kSociumSetupMultiplyGate, gate_id_, payload2);
    communication_layer.SendMessage(1, message2.Release());
  } else {
    auto message = matrix_multiply_future_setup_.get();
    const auto payload = communication::GetMessage(message.data())->payload();
    DeserializeMatrices(out_value_matrices, std::span<uint8_t const>{payload->Data(), payload->size()});
  }
}

template<typename T>
void SociumFpaMatrixMultiplicationConstantGate<T>::EvaluateOnline() {
  using communication::MessageType::kSociumOnlineMultiplyGate;
  using boost::numeric::ublas::matrix;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = 
    std::dynamic_pointer_cast<swift::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire =
    std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_[0]);
  assert(matrix_a_wire);
  size_t const number_of_simd_values = 
    matrix_a_wire->GetNumberOfSimdValues();
  assert(matrix_out_wire->GetNumberOfSimdValues() == number_of_simd_values);
  WaitSetup();
  assert(setup_is_ready_);
  parent_[0]->GetIsReadyCondition().Wait();
  
  auto& a_value_matrices =
    matrix_a_wire->GetMutableValueMatrices();
  auto& a_my_id_lambda_matrices =
    matrix_a_wire->GetMutableLambdaMyIdMatrices();
  auto& a_previous_id_lambda_matrices =
    matrix_a_wire->GetMutableLambdaPreviousIdMatrices();
  auto& out_value_matrices =
    matrix_out_wire->GetMutableValueMatrices();
  auto& out_my_id_lambda_matrices =
    matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_previous_id_lambda_matrices =
    matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  
  size_t const u = a_value_matrices[0].size1();
  size_t const v = a_value_matrices[0].size2();

  if (my_id == 1) {
    std::vector<matrix<T>> t1;
    t1.reserve(number_of_simd_values);
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      t1.emplace_back(u, v);
      t1[s] = constant_ * (a_value_matrices[s] + a_my_id_lambda_matrices[s]);
    }
    Truncate(t1, precision_);
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      t1[s] = t1[s] - out_my_id_lambda_matrices[s];
      out_value_matrices[s] = out_value_matrices[s] + t1[s] - out_previous_id_lambda_matrices[s];
    }

    {
      auto payload = SerializeMatrices(t1);
      auto message = 
        communication::BuildMessage(kSociumOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(0, message.Release());
    }
  } else if (my_id == 2) {
    std::vector<matrix<T>> t1;
    t1.reserve(number_of_simd_values);
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      t1.emplace_back(u, v);
      t1[s] = constant_ * (a_value_matrices[s] + a_previous_id_lambda_matrices[s]);
    }
    Truncate(t1, precision_);
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      t1[s] = t1[s] - out_previous_id_lambda_matrices[s];
      out_value_matrices[s] = out_value_matrices[s] + t1[s] - out_my_id_lambda_matrices[s];
    }
  } else if (my_id == 0) {
    auto message = matrix_multiply_future_online_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    std::vector<matrix<T>> t1 = 
      CreateMatrices<T>(u, v, number_of_simd_values);
    DeserializeMatrices(t1, std::span<uint8_t const>{payload->Data(), payload->size()});
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      out_value_matrices[s] += t1[s] - out_my_id_lambda_matrices[s];
    }
  }
}

template class SociumFpaMatrixMultiplicationConstantGate<std::uint8_t>;
template class SociumFpaMatrixMultiplicationConstantGate<std::uint16_t>;
template class SociumFpaMatrixMultiplicationConstantGate<std::uint32_t>;
template class SociumFpaMatrixMultiplicationConstantGate<std::uint64_t>;

template<typename T>
BitAGate<T>::BitAGate(BitMatrixWirePointer bit_matrix_wire)
: OneGate(bit_matrix_wire->GetBackend()),
  triple_(backend_.GetSwiftVerifier()->ReserveTriples128(
    2 * bit_matrix_wire->GetMatrixSimdValues() 
      * bit_matrix_wire->GetNumberOfRows()
      * bit_matrix_wire->GetNumberOfColumns())) {
  using communication::MessageType::kSwiftBitASetupD;
  using communication::MessageType::kSwiftBitASetupF;
  using communication::MessageType::kSwiftBitAOnline;
  
  parent_ = {bit_matrix_wire};
  
  size_t u = bit_matrix_wire->GetNumberOfRows();
  size_t v = bit_matrix_wire->GetNumberOfColumns();
  size_t number_of_simd_values = bit_matrix_wire->GetMatrixSimdValues();

  output_wires_ = 
    {GetRegister().template EmplaceWire<MatrixWire<T>>(
       backend_, u, v, number_of_simd_values)};

  uint64_t my_id = GetCommunicationLayer().GetMyId();
  uint64_t previous_id = (my_id + 2) % 3;
  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  
  bit_a_future_setup_d_ = 
    message_manager.RegisterReceive(previous_id, kSwiftBitASetupD, gate_id_);
  bit_a_future_setup_f_ = 
    message_manager.RegisterReceive(previous_id, kSwiftBitASetupF, gate_id_);
    
  if(my_id == 0) {
    bit_a_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftBitAOnline, gate_id_);
  } else if(my_id == 1) {
    bit_a_future_online_ = 
      message_manager.RegisterReceive(2, kSwiftBitAOnline, gate_id_);
  } else if(my_id == 2) {
    bit_a_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftBitAOnline, gate_id_);
  }
   
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    //We are S_0, so we reserve hash memory for the hash we will receive from S2
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        number_of_simd_values * sizeof(T), 2);
    //we also reserve memory for the hash we will be sending to S1 and S2
    verifier_s1_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        number_of_simd_values * sizeof(T), 1);
    verifier_s2_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        number_of_simd_values * sizeof(T), 2);
  } else {
    //We are S1 or S2 and thus will receive a hash from S0;
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        number_of_simd_values * sizeof(T), 0);
  }
  
  if(my_id == 2) {
    //We reserve memory for the hash we will be sending to S0
    verifier_s2_message_data_ = 
      multipy_hash_verifier->ReserveHashMessage(
        number_of_simd_values * sizeof(T), 0);
  }
}

template<typename T>
void BitAGate<T>::EvaluateSetup() {
  using boost::numeric::ublas::matrix;
  using communication::MessageType::kSwiftBitASetupD;
  using communication::MessageType::kSwiftBitASetupF;
  
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  auto bit_matrix_wire = 
    std::dynamic_pointer_cast<BitMatrixWire>(parent_[0]);
  assert(bit_matrix_wire);
  auto matrix_out_wire = 
    std::dynamic_pointer_cast<MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto& bit_matrix_lambdas_my_id = 
    bit_matrix_wire->GetLambdasMyId();
  auto& bit_matrix_lambdas_previous_id = 
    bit_matrix_wire->GetLambdasPreviousId();
  auto& out_lambda_my_id_matrices = 
    matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_lambda_previous_id_matrices = 
    matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  
  size_t const u = bit_matrix_wire->GetNumberOfRows();
  size_t const v = bit_matrix_wire->GetNumberOfColumns();
  size_t const number_of_simd_values = 
    bit_matrix_wire->GetMatrixSimdValues();
  
  size_t const alpha_bytes = 
    u * v * number_of_simd_values * sizeof(UInt128);
  size_t const lambda_z_bytes = 
    u * v * number_of_simd_values * sizeof(T);
  size_t const random_bytes = 2 * alpha_bytes + lambda_z_bytes;
  
  
  auto& rng_i = 
    backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
  auto& rng_i_minus_1 = 
    backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
  std::vector<uint8_t> randoms_my_id = 
    rng_i.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
  std::vector<uint8_t> randoms_previous_id = 
    rng_i_minus_1.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
    
  {
    size_t offset = 0;
    uint8_t* lambda_my_id_z_pointer = 
      randoms_my_id.data() + 2*alpha_bytes;
    uint8_t* lambda_previous_id_z_pointer = 
      randoms_previous_id.data() + 2*alpha_bytes;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          T lambda_my_id_z_value, lambda_previous_id_z_value;
          memcpy(&lambda_my_id_z_value, 
                 lambda_my_id_z_pointer, 
                 sizeof(T));
          memcpy(&lambda_previous_id_z_value, 
                 lambda_previous_id_z_pointer, 
                 sizeof(T));
          out_lambda_my_id_matrices[s](i, j) = 
            lambda_my_id_z_value;
          out_lambda_previous_id_matrices[s](i, j) = 
            lambda_previous_id_z_value;
          offset += sizeof(T);
        }
      }
    }
  }
  matrix_out_wire->SetSetupIsReady();
  
  bit_matrix_wire->GetSetupReadyCondition()->Wait();
  //Calculate D_my_id, D_previous_id
  std::vector<matrix<UInt128>> D_my_id;
  D_my_id.reserve(number_of_simd_values);
  {
    size_t offset = 0;
    size_t bit_offset = 0;
    uint8_t const* const alpha_my_id_pointer = 
      randoms_my_id.data();
    uint8_t const* const alpha_previous_id_pointer = 
      randoms_previous_id.data();
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      D_my_id.emplace_back(u, v);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          UInt128 alpha_my_id, alpha_previous_id;
          memcpy(&alpha_my_id, 
                 alpha_my_id_pointer + offset, 
                 sizeof(UInt128));
          memcpy(&alpha_previous_id, 
                 alpha_previous_id_pointer + offset, 
                 sizeof(UInt128));
          switch(my_id) {
            case 0: {
              //Since b_0 = 0, b_2 = 0 and a_2 = 0,
              //a_0 * b_0 + a_0 * b_2 + a_2 * b_0 = 0
              D_my_id[s](i, j) = alpha_my_id - alpha_previous_id;
              break;
            }
            case 1: {
              UInt128 a_0 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 b_1 = bit_matrix_lambdas_my_id.Get(bit_offset);
              D_my_id[s](i, j) = a_0 * b_1 + alpha_my_id - alpha_previous_id;
              break;
            }
            case 2: {
              //Since a_2 = 0, a_1 = 0 and b_2 = 0,
              //a_2 * b_2 + a_2 * b_1 + a_1 * b_2 = 0
              D_my_id[s](i, j) = alpha_my_id - alpha_previous_id;
              break;
            }
          }
          offset += sizeof(UInt128);
          bit_offset += 1;
        }
      }
    }
  }
  std::vector<matrix<UInt128>> D_previous_id = 
    CreateMatrices<UInt128>(u, v, number_of_simd_values);
  
  {
    auto payload = SerializeMatrices(D_my_id);
    auto message = 
      communication::BuildMessage(kSwiftBitASetupD, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  
  {
    auto message = bit_a_future_setup_d_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    DeserializeMatrices(
      D_previous_id, std::span<uint8_t const>{payload->Data(), payload->size()});
  }

  //Append triples
  {
    size_t bit_offset = 0;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          switch(my_id) {
            case 0: {
              UInt128 a_0 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 a_2 = 0; 
              UInt128 b_0 = 0;
              UInt128 b_2 = 0;
              UInt128 d_0 = D_my_id[s](i, j); 
              UInt128 d_2 = D_previous_id[s](i, j);
              triple_.AppendTriple(a_0, a_2, b_0, b_2, d_0, d_2);
              break;
            }
            case 1: {
              UInt128 a_0 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 a_1 = 0;
              UInt128 b_0 = 0;
              UInt128 b_1 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 d_0 = D_previous_id[s](i, j);
              UInt128 d_1 = D_my_id[s](i, j);
              triple_.AppendTriple(a_1, a_0, b_1, b_0, d_1, d_0);
              break;
            }
            case 2: {
              UInt128 a_1 = 0;
              UInt128 a_2 = 0;
              UInt128 b_1 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 b_2 = 0;
              UInt128 d_1 = D_previous_id[s](i, j);
              UInt128 d_2 = D_my_id[s](i, j);
              triple_.AppendTriple(a_2, a_1, b_2, b_1, d_2, d_1);
              break;
            }
          }
          bit_offset += 1;
        }
      }
    }
  }
  
  //Calculate F_my_id, F_previous_id
  std::vector<matrix<UInt128>> F_my_id;
  F_my_id.reserve(number_of_simd_values);

  {
    size_t offset = 0;
    size_t bit_offset = 0;
    uint8_t const* const alpha_my_id_pointer = 
      randoms_my_id.data() + alpha_bytes;
    uint8_t const* const alpha_previous_id_pointer = 
      randoms_previous_id.data() + alpha_bytes;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      F_my_id.emplace_back(u, v);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          UInt128 alpha_my_id, alpha_previous_id;
          memcpy(&alpha_my_id, 
                 alpha_my_id_pointer + offset, 
                 sizeof(UInt128));
          memcpy(&alpha_previous_id, 
                 alpha_previous_id_pointer + offset, 
                 sizeof(UInt128));
          switch(my_id) {
            case 0: {
              UInt128 a_0 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 c_2 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 E_0_value = a_0 - 2*D_my_id[s](i, j);
              F_my_id[s](i, j) = 
                c_2 * E_0_value + alpha_my_id - alpha_previous_id;
              break;
            }
            case 1: {
              //Since c_0 = 0 and c_1 = 0,
              //c_1 * E_1 + c_1 * E_0 + c_0 * E_1 = 0
              F_my_id[s](i, j) = alpha_my_id - alpha_previous_id;
              break;
            }
            case 2: {
              UInt128 b_1 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 c_2 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 E_1_value = b_1 - 2*D_my_id[s](i, j);
              UInt128 E_2_value = -2*D_previous_id[s](i, j);
              F_my_id[s](i, j) = 
                c_2 * E_2_value + c_2 * E_1_value 
                + alpha_my_id - alpha_previous_id;
              break;
            }
          }
          offset += sizeof(UInt128);
          bit_offset += 1;
        }
      }
    }
  }
  std::vector<matrix<UInt128>> F_previous_id = 
    CreateMatrices<UInt128>(u, v, number_of_simd_values);
  
  {
    auto payload = SerializeMatrices(F_my_id);
    auto message = 
      communication::BuildMessage(kSwiftBitASetupF, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  
  {
    auto message = bit_a_future_setup_f_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    DeserializeMatrices(
      F_previous_id, std::span<uint8_t const>{payload->Data(), payload->size()});
  }

  //Append triples
  {
    size_t bit_offset = 0;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          switch(my_id) {
            case 0: {
              UInt128 a_0 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 c_0 = 0;
              UInt128 c_2 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 d_0 = D_my_id[s](i, j);
              UInt128 d_2 = D_previous_id[s](i, j);
              UInt128 e_0 = a_0 - 2*d_0;
              UInt128 e_2 = -2*d_2;
              UInt128 f_0 = F_my_id[s](i, j); 
              UInt128 f_2 = F_previous_id[s](i, j);
              triple_.AppendTriple(c_0, c_2, e_0, e_2, f_0, f_2);
              break;
            }
            case 1: {
              UInt128 a_0 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 b_1 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 c_0 = 0;
              UInt128 c_1 = 0;
              UInt128 d_0 = D_previous_id[s](i, j);
              UInt128 d_1 = D_my_id[s](i, j);
              UInt128 e_0 = a_0 - 2*d_0;
              UInt128 e_1 = b_1 - 2*d_1;
              UInt128 f_0 = F_previous_id[s](i, j); 
              UInt128 f_1 = F_my_id[s](i, j);
              triple_.AppendTriple(c_1, c_0, e_1, e_0, f_1, f_0);
              break;
            }
            case 2: {
              UInt128 b_1 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 c_1 = 0;
              UInt128 c_2 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 d_1 = D_previous_id[s](i, j);
              UInt128 d_2 = D_my_id[s](i, j);
              UInt128 e_1 = b_1 - 2*d_1;
              UInt128 e_2 = -2*d_2;
              UInt128 f_1 = F_previous_id[s](i, j);
              UInt128 f_2 = F_my_id[s](i, j);
              triple_.AppendTriple(c_2, c_1, e_2, e_1, f_2, f_1);
              break;
            }
          }
          bit_offset += 1;
        }
      }
    }
  }
  backend_.GetSwiftVerifier()->SetReady();
  
  //Calculate H
  H_my_id.reserve(number_of_simd_values);
  H_previous_id.reserve(number_of_simd_values);
  {
    size_t offset = 0;
    size_t bit_offset = 0;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      H_my_id.emplace_back(u, v);
      H_previous_id.emplace_back(u, v);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          switch(my_id) {
            case 0: {
              UInt128 a_0 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 c_2 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 E_0_value = a_0 - 2*D_my_id[s](i, j);
              UInt128 E_2_value = -2*D_previous_id[s](i, j);
              UInt128 G_0_value = E_0_value - 2*F_my_id[s](i, j);
              UInt128 G_2_value = c_2 + E_2_value - 2*F_previous_id[s](i, j);
              H_my_id[s](i, j) = T(G_0_value);
              H_previous_id[s](i, j) = T(G_2_value);
              break;
            }
            case 1: {
              UInt128 a_0 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 b_1 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 E_0_value = a_0 - 2*D_my_id[s](i, j);
              UInt128 E_1_value = b_1 - 2*D_my_id[s](i, j);
              UInt128 G_0_value = E_0_value - 2*F_previous_id[s](i, j);
              UInt128 G_1_value = E_1_value - 2*F_my_id[s](i, j);
              H_previous_id[s](i, j) = T(G_0_value);
              H_my_id[s](i, j) = T(G_1_value);
              break;
            }
            case 2: {
              UInt128 b_1 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 c_2 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 E_1_value = b_1 - 2*D_my_id[s](i, j);
              UInt128 E_2_value = -2*D_previous_id[s](i, j);
              UInt128 G_1_value = E_1_value - 2*F_previous_id[s](i, j);
              UInt128 G_2_value = c_2 + E_2_value - 2*F_my_id[s](i, j);
              H_previous_id[s](i, j) = T(G_1_value);
              H_my_id[s](i, j) = T(G_2_value);
              break;
            }
          }
          offset += sizeof(UInt128);
          bit_offset += 1;
        }
      }
    }
  }
}

template<typename T>
void BitAGate<T>::EvaluateOnline() {
  using boost::numeric::ublas::matrix;
  using communication::MessageType::kSwiftBitAOnline;
  
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  auto bit_matrix_wire = 
    std::dynamic_pointer_cast<BitMatrixWire>(parent_[0]);
  assert(bit_matrix_wire);
  auto matrix_out_wire = 
    std::dynamic_pointer_cast<MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto& bit_matrix_values = bit_matrix_wire->GetValues();
  auto& out_lambda_my_id_matrices = 
    matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_lambda_previous_id_matrices = 
    matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  auto& out_value_matrices = 
    matrix_out_wire->GetMutableValueMatrices();
    
  size_t const u = bit_matrix_wire->GetNumberOfRows();
  size_t const v = bit_matrix_wire->GetNumberOfColumns();
  size_t const number_of_simd_values = 
    bit_matrix_wire->GetMatrixSimdValues();
    
  WaitSetup();
  assert(setup_is_ready_);
  parent_[0]->GetIsReadyCondition().Wait();
  
  std::vector<matrix<T>> lambda_Y_my_id, lambda_Y_previous_id;
  lambda_Y_my_id.reserve(number_of_simd_values);
  lambda_Y_previous_id.reserve(number_of_simd_values);
  {
    size_t bit_offset = 0;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      lambda_Y_my_id.emplace_back(u, v);
      lambda_Y_previous_id.emplace_back(u, v);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          lambda_Y_my_id[s](i, j) = 
            H_my_id[s](i, j) * (1 - 2*bit_matrix_values[bit_offset])
            - out_lambda_my_id_matrices[s](i, j);
          lambda_Y_previous_id[s](i, j) = 
            H_previous_id[s](i, j) * (1 - 2*bit_matrix_values[bit_offset])
            - out_lambda_previous_id_matrices[s](i, j);
          bit_offset += 1;
        }
      }
    }
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    verifier_s1_message_data_.AssignData(lambda_Y_previous_id);
    multipy_hash_verifier->SetReady();
    verifier_s2_message_data_.AssignData(lambda_Y_my_id);
    multipy_hash_verifier->SetReady();
  }
  else if(my_id == 1) {
    //We are S1 so we send lambda_Y_0 to S2, which is lambda_Y_previous_id
    //and lambda_Y_1 to S0, which is lambda_Y_my_id
    {
      auto payload = SerializeMatrices(lambda_Y_previous_id);
      auto message = 
        communication::BuildMessage(kSwiftBitAOnline, gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
    }
    
    {
      auto payload = SerializeMatrices(lambda_Y_my_id);
      auto message = 
        communication::BuildMessage(kSwiftBitAOnline, gate_id_, payload);
      communication_layer.SendMessage(0, message.Release());
    }
  } else if(my_id == 2) {
    //We are S2 so we send lambda_Y_2 to S1, which is lambda_Y_my_id
    //and H(lambda_Y_1) which is H(lambda_Y_previous_id)
    {
      auto payload = SerializeMatrices(lambda_Y_my_id);
      auto message = 
        communication::BuildMessage(kSwiftBitAOnline, gate_id_, payload);
      communication_layer.SendMessage(1, message.Release());
    }
    verifier_s2_message_data_.AssignData(lambda_Y_previous_id);
    multipy_hash_verifier->SetReady();
  } else {
    assert(false);
  }
  
  {
    auto message = bit_a_future_online_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    std::vector<matrix<T>> lambda_Y_missing_id = 
      CreateMatrices<T>(u, v, number_of_simd_values);
    DeserializeMatrices(
      lambda_Y_missing_id, std::span<uint8_t const>{payload->Data(), payload->size()});
    
    {
      size_t bit_offset = 0;
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        for(size_t i = 0; i != u; ++i) {
          for(size_t j = 0; j != v; ++j) {
            out_value_matrices[s](i, j) = 
              bit_matrix_values[bit_offset] + lambda_Y_previous_id[s](i, j)
              + lambda_Y_my_id[s](i, j) + lambda_Y_missing_id[s](i, j);
            bit_offset += 1;
          }
        }
      }
    }
    
    verifier_received_hash_data_.AssignData(lambda_Y_missing_id);
    multipy_hash_verifier->SetReady();
  }
}

template class BitAGate<std::uint8_t>;
template class BitAGate<std::uint16_t>;
template class BitAGate<std::uint32_t>;
template class BitAGate<std::uint64_t>;

template<typename T>
SociumBitAGate<T>::SociumBitAGate(BitMatrixWirePointer bit_matrix_wire)
: OneGate(bit_matrix_wire->GetBackend()),
  triple_(backend_.GetSociumVerifier()->ReserveTriples128(
    2 * bit_matrix_wire->GetMatrixSimdValues() 
      * bit_matrix_wire->GetNumberOfRows()
      * bit_matrix_wire->GetNumberOfColumns())) {
  using communication::MessageType::kSwiftBitASetupD;
  using communication::MessageType::kSwiftBitASetupF;
  using communication::MessageType::kSwiftBitAOnline;
  
  parent_ = {bit_matrix_wire};
  
  size_t u = bit_matrix_wire->GetNumberOfRows();
  size_t v = bit_matrix_wire->GetNumberOfColumns();
  size_t number_of_simd_values = bit_matrix_wire->GetMatrixSimdValues();

  output_wires_ = 
    {GetRegister().template EmplaceWire<MatrixWire<T>>(
       backend_, u, v, number_of_simd_values)};

  uint64_t my_id = GetCommunicationLayer().GetMyId();
  uint64_t previous_id = (my_id + 2) % 3;
  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  
  bit_a_future_setup_d_ = 
    message_manager.RegisterReceive(previous_id, kSwiftBitASetupD, gate_id_);
  if (my_id != 2) { // S2 does not receive in second setup mult
    bit_a_future_setup_f_ = 
      message_manager.RegisterReceive(previous_id, kSwiftBitASetupF, gate_id_);
  }
    
  if(my_id == 0) {
    bit_a_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftBitAOnline, gate_id_);
  } else if(my_id == 1) {
    bit_a_future_online_ = 
      message_manager.RegisterReceive(2, kSwiftBitAOnline, gate_id_);
  } else if(my_id == 2) {
    bit_a_future_online_ = 
      message_manager.RegisterReceive(1, kSwiftBitAOnline, gate_id_);
  }
   
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    //We are S_0, so we reserve memory for the hash we will be sending to S1
    verifier_s1_message_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        number_of_simd_values * sizeof(T), 1);
  } else if (my_id == 1) {
    //We are S1 and thus will receive a hash from S0;
    verifier_received_hash_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        number_of_simd_values * sizeof(T), 0);
  }
}

template<typename T>
void SociumBitAGate<T>::EvaluateSetup() {
  using boost::numeric::ublas::matrix;
  using communication::MessageType::kSwiftBitASetupD;
  using communication::MessageType::kSwiftBitASetupF;
  
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  auto bit_matrix_wire = 
    std::dynamic_pointer_cast<BitMatrixWire>(parent_[0]);
  assert(bit_matrix_wire);
  auto matrix_out_wire = 
    std::dynamic_pointer_cast<MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto& bit_matrix_lambdas_my_id = 
    bit_matrix_wire->GetLambdasMyId();
  auto& bit_matrix_lambdas_previous_id = 
    bit_matrix_wire->GetLambdasPreviousId();
  auto& out_lambda_my_id_matrices = 
    matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_lambda_previous_id_matrices = 
    matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  
  size_t const u = bit_matrix_wire->GetNumberOfRows();
  size_t const v = bit_matrix_wire->GetNumberOfColumns();
  size_t const number_of_simd_values = 
    bit_matrix_wire->GetMatrixSimdValues();
  
  size_t const alpha_bytes = 
    u * v * number_of_simd_values * sizeof(UInt128);
  size_t const lambda_z_bytes = 
    u * v * number_of_simd_values * sizeof(T);
  size_t const random_bytes = 2 * alpha_bytes + lambda_z_bytes;
  
  
  auto& rng_i = 
    backend_.GetBaseProvider().GetMyRandomnessGenerator(next_id);
  auto& rng_i_minus_1 = 
    backend_.GetBaseProvider().GetTheirRandomnessGenerator(previous_id);
  std::vector<uint8_t> randoms_my_id = 
    rng_i.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
  std::vector<uint8_t> randoms_previous_id = 
    rng_i_minus_1.template GetUnsigned<uint8_t>(gate_id_, random_bytes);
    
  {
    size_t offset = 0;
    uint8_t* lambda_my_id_z_pointer = 
      randoms_my_id.data() + 2*alpha_bytes;
    uint8_t* lambda_previous_id_z_pointer = 
      randoms_previous_id.data() + 2*alpha_bytes;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          T lambda_my_id_z_value, lambda_previous_id_z_value;
          memcpy(&lambda_my_id_z_value, 
                 lambda_my_id_z_pointer, 
                 sizeof(T));
          memcpy(&lambda_previous_id_z_value, 
                 lambda_previous_id_z_pointer, 
                 sizeof(T));
          out_lambda_my_id_matrices[s](i, j) = 
            lambda_my_id_z_value;
          out_lambda_previous_id_matrices[s](i, j) = 
            lambda_previous_id_z_value;
          offset += sizeof(T);
        }
      }
    }
  }
  matrix_out_wire->SetSetupIsReady();
    
  //We don't actually compute matrices A (lambda_0), B (lambda_1), C (lambda_2)
  
  //Calculate D_my_id, D_previous_id where D = A [component wise *] B. 
  // This is a SWIFT setup mult as we need to chain it with another setup mult that then is Socium
  std::vector<matrix<UInt128>> D_my_id;
  D_my_id.reserve(number_of_simd_values);
  bit_matrix_wire->GetSetupReadyCondition()->Wait();
  {
    size_t offset = 0;
    size_t bit_offset = 0;
    uint8_t const* const alpha_my_id_pointer = 
      randoms_my_id.data();
    uint8_t const* const alpha_previous_id_pointer = 
      randoms_previous_id.data();
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      D_my_id.emplace_back(u, v);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          UInt128 alpha_my_id, alpha_previous_id;
          memcpy(&alpha_my_id, 
                 alpha_my_id_pointer + offset, 
                 sizeof(UInt128));
          memcpy(&alpha_previous_id, 
                 alpha_previous_id_pointer + offset, 
                 sizeof(UInt128));
          switch(my_id) {
            case 0: {
              //Since b_0 = 0, b_2 = 0 and a_2 = 0,
              //a_0 * b_0 + a_0 * b_2 + a_2 * b_0 = 0
              D_my_id[s](i, j) = alpha_my_id - alpha_previous_id;
              break;
            }
            case 1: {
              // Since a_1 = b_0 = 0,
              // a_1 * b_1 + a_1 * b_0 + a_0 * b_1 = a_0 * b_1
              UInt128 a_0 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 b_1 = bit_matrix_lambdas_my_id.Get(bit_offset);
              D_my_id[s](i, j) = a_0 * b_1 + alpha_my_id - alpha_previous_id;
              break;
            }
            case 2: {
              //Since a_2 = 0, a_1 = 0 and b_2 = 0,
              //a_2 * b_2 + a_2 * b_1 + a_1 * b_2 = 0
              D_my_id[s](i, j) = alpha_my_id - alpha_previous_id;
              break;
            }
          }
          offset += sizeof(UInt128);
          bit_offset += 1;
        }
      }
    }
  }
  std::vector<matrix<UInt128>> D_previous_id = 
    CreateMatrices<UInt128>(u, v, number_of_simd_values);
  
  {
    auto payload = SerializeMatrices(D_my_id);
    auto message = 
      communication::BuildMessage(kSwiftBitASetupD, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  
  {
    auto message = bit_a_future_setup_d_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    DeserializeMatrices(
      D_previous_id, std::span<uint8_t const>{payload->Data(), payload->size()});
  }

  //Append triples
  {
    size_t bit_offset = 0;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          switch(my_id) {
            case 0: {
              UInt128 a_0 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 a_2 = 0; 
              UInt128 b_0 = 0;
              UInt128 b_2 = 0;
              UInt128 d_0 = D_my_id[s](i, j); 
              UInt128 d_2 = D_previous_id[s](i, j);
              triple_.AppendTriple(a_0, a_2, b_0, b_2, d_0, d_2);
              break;
            }
            case 1: {
              UInt128 a_0 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 a_1 = 0;
              UInt128 b_0 = 0;
              UInt128 b_1 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 d_0 = D_previous_id[s](i, j);
              UInt128 d_1 = D_my_id[s](i, j);
              triple_.AppendTriple(a_1, a_0, b_1, b_0, d_1, d_0);
              break;
            }
            case 2: {
              UInt128 a_1 = 0;
              UInt128 a_2 = 0;
              UInt128 b_1 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 b_2 = 0;
              UInt128 d_1 = D_previous_id[s](i, j); // is ignored anyways as Socium
              UInt128 d_2 = D_my_id[s](i, j);
              triple_.AppendTriple(a_2, a_1, b_2, b_1, d_2, d_1);
              break;
            }
          }
          bit_offset += 1;
        }
      }
    }
  }
  
  //Calculate F_my_id, F_previous_id where F = C [component wise *] (A + B - 2 * D).
  // A + B - 2 * D = E
  // This is normal Socium setup mult
  std::vector<matrix<UInt128>> F_my_id;
  F_my_id.reserve(number_of_simd_values);
  {
    size_t offset = 0;
    size_t bit_offset = 0;
    uint8_t const* const alpha_my_id_pointer = 
      randoms_my_id.data() + alpha_bytes;
    uint8_t const* const alpha_previous_id_pointer = 
      randoms_previous_id.data() + alpha_bytes;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      F_my_id.emplace_back(u, v);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          UInt128 alpha_my_id, alpha_previous_id;
          memcpy(&alpha_my_id, 
                 alpha_my_id_pointer + offset, 
                 sizeof(UInt128));
          memcpy(&alpha_previous_id, 
                 alpha_previous_id_pointer + offset, 
                 sizeof(UInt128));
          switch(my_id) {
            case 0: {
              //Since c_0 = 0,
              // c_0 * e_0 + c_0 * e_2 + c_2 * e_0 = c_2 * e_0.
              // Also, since b_0 = 0,
              // a_0 + b_0 - 2 * d_0 = a_0 - 2 * d_0.
              UInt128 a_0 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 c_2 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 E_0_value = a_0 - 2*D_my_id[s](i, j);
              F_my_id[s](i, j) = 
                c_2 * E_0_value + alpha_my_id - alpha_previous_id;
              break;
            }
            case 1: {
              //Since c_0 = 0 and c_1 = 0,
              //c_1 * E_1 + c_1 * E_0 + c_0 * E_1 = 0
              F_my_id[s](i, j) = alpha_my_id - alpha_previous_id;
              break;
            }
            case 2: {
              //Since c_1 = 0,
              // c_2 * e_2 + c_2 * e_1 + c_1 * e_2 = c_2 * e_2 + c_2 * e_1.
              // Also, since b_2 = b_2 = a_1 = 0,
              // a_2 + b_2 - 2 * d_2 = - 2 * d_0 and
              // a_1 + b_1 - 2 * d_1 = b_1 - 2 * d_0.
              UInt128 b_1 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 c_2 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 E_1_value = b_1 - 2*D_my_id[s](i, j);
              UInt128 E_2_value = -2*D_previous_id[s](i, j);
              F_my_id[s](i, j) = 
                c_2 * E_2_value + c_2 * E_1_value 
                + alpha_my_id - alpha_previous_id;
              break;
            }
          }
          offset += sizeof(UInt128);
          bit_offset += 1;
        }
      }
    }
  }
  std::vector<matrix<UInt128>> F_previous_id = 
    CreateMatrices<UInt128>(u, v, number_of_simd_values);
  
  if (my_id == 0 || my_id == 2) { // S1 does not send in Socium
    auto payload = SerializeMatrices(F_my_id);
    auto message = 
      communication::BuildMessage(kSwiftBitASetupF, gate_id_, payload);
    communication_layer.SendMessage(next_id, message.Release());
  }
  
  if (my_id == 0 || my_id == 1) { // S2 does not receive in Socium
    auto message = bit_a_future_setup_f_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    DeserializeMatrices(
      F_previous_id, std::span<uint8_t const>{payload->Data(), payload->size()});
  }

  //Append triples
  {
    size_t bit_offset = 0;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          switch(my_id) {
            case 0: {
              UInt128 a_0 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 c_0 = 0;
              UInt128 c_2 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 d_0 = D_my_id[s](i, j);
              UInt128 d_2 = D_previous_id[s](i, j);
              UInt128 e_0 = a_0 - 2*d_0;
              UInt128 e_2 = -2*d_2;
              UInt128 f_0 = F_my_id[s](i, j); 
              UInt128 f_2 = F_previous_id[s](i, j);
              triple_.AppendTriple(c_0, c_2, e_0, e_2, f_0, f_2);
              break;
            }
            case 1: {
              UInt128 a_0 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 b_1 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 c_0 = 0;
              UInt128 c_1 = 0;
              UInt128 d_0 = D_previous_id[s](i, j);
              UInt128 d_1 = D_my_id[s](i, j);
              UInt128 e_0 = a_0 - 2*d_0;
              UInt128 e_1 = b_1 - 2*d_1;
              UInt128 f_0 = F_previous_id[s](i, j); 
              UInt128 f_1 = F_my_id[s](i, j);
              triple_.AppendTriple(c_1, c_0, e_1, e_0, f_1, f_0);
              break;
            }
            case 2: {
              UInt128 b_1 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 c_1 = 0;
              UInt128 c_2 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 d_1 = D_previous_id[s](i, j);
              UInt128 d_2 = D_my_id[s](i, j);
              UInt128 e_1 = b_1 - 2*d_1;
              UInt128 e_2 = -2*d_2;
              UInt128 empty = 0; // Socium
              UInt128 f_2 = F_my_id[s](i, j);
              triple_.AppendTriple(c_2, c_1, e_2, e_1, f_2, empty);
              break;
            }
          }
          bit_offset += 1;
        }
      }
    }
  }
  backend_.GetSociumVerifier()->SetReady();
  
  //Calculate H
  H_my_id.reserve(number_of_simd_values);
  if (my_id == 0 || my_id == 1) { // Incomplete sharing, S2 does not have previous
    H_previous_id.reserve(number_of_simd_values);
  }
  {
    size_t offset = 0;
    size_t bit_offset = 0;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      H_my_id.emplace_back(u, v);
      H_previous_id.emplace_back(u, v);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          switch(my_id) {
            case 0: {
              UInt128 a_0 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 c_2 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 E_0_value = a_0 - 2*D_my_id[s](i, j);
              UInt128 E_2_value = -2*D_previous_id[s](i, j);
              UInt128 G_0_value = E_0_value - 2*F_my_id[s](i, j);
              UInt128 G_2_value = c_2 + E_2_value - 2*F_previous_id[s](i, j);
              H_my_id[s](i, j) = T(G_0_value);
              H_previous_id[s](i, j) = T(G_2_value);
              break;
            }
            case 1: {
              UInt128 a_0 = bit_matrix_lambdas_previous_id.Get(bit_offset);
              UInt128 b_1 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 E_0_value = a_0 - 2*D_my_id[s](i, j);
              UInt128 E_1_value = b_1 - 2*D_my_id[s](i, j);
              UInt128 G_0_value = E_0_value - 2*F_previous_id[s](i, j);
              UInt128 G_1_value = E_1_value - 2*F_my_id[s](i, j);
              H_previous_id[s](i, j) = T(G_0_value);
              H_my_id[s](i, j) = T(G_1_value);
              break;
            }
            case 2: {
              UInt128 c_2 = bit_matrix_lambdas_my_id.Get(bit_offset);
              UInt128 E_2_value = -2*D_previous_id[s](i, j);
              UInt128 G_2_value = c_2 + E_2_value - 2*F_my_id[s](i, j);
              H_my_id[s](i, j) = T(G_2_value);
              break;
            }
          }
          offset += sizeof(UInt128);
          bit_offset += 1;
        }
      }
    }
  }
}

template<typename T>
void SociumBitAGate<T>::EvaluateOnline() {
  using boost::numeric::ublas::matrix;
  using communication::MessageType::kSwiftBitAOnline;
  
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  auto bit_matrix_wire = 
    std::dynamic_pointer_cast<BitMatrixWire>(parent_[0]);
  assert(bit_matrix_wire);
  auto matrix_out_wire = 
    std::dynamic_pointer_cast<MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto& bit_matrix_values = bit_matrix_wire->GetValues();
  auto& out_lambda_my_id_matrices = 
    matrix_out_wire->GetMutableLambdaMyIdMatrices();
  auto& out_lambda_previous_id_matrices = 
    matrix_out_wire->GetMutableLambdaPreviousIdMatrices();
  auto& out_value_matrices = 
    matrix_out_wire->GetMutableValueMatrices();
    
  size_t const u = bit_matrix_wire->GetNumberOfRows();
  size_t const v = bit_matrix_wire->GetNumberOfColumns();
  size_t const number_of_simd_values = 
    bit_matrix_wire->GetMatrixSimdValues();
    
  WaitSetup();
  assert(setup_is_ready_);
  parent_[0]->GetIsReadyCondition().Wait();
  
  std::vector<matrix<T>> lambda_Y_my_id, lambda_Y_previous_id;
  lambda_Y_my_id.reserve(number_of_simd_values);
  lambda_Y_previous_id.reserve(number_of_simd_values); // For S1, this will be Y0+Y1
  {
    size_t bit_offset = 0;
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      lambda_Y_my_id.emplace_back(u, v);
      lambda_Y_previous_id.emplace_back(u, v);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          lambda_Y_my_id[s](i, j) = 
            H_my_id[s](i, j) * (1 - 2*bit_matrix_values[bit_offset])
            - out_lambda_my_id_matrices[s](i, j);
          if (my_id == 0 || my_id == 1) { // Socium, so S2 does not have H1
            lambda_Y_previous_id[s](i, j) = 
              H_previous_id[s](i, j) * (1 - 2*bit_matrix_values[bit_offset])
              - out_lambda_previous_id_matrices[s](i, j);
          }
          if (my_id == 1) { // see above, Y0+Y1
            lambda_Y_previous_id[s](i, j) += lambda_Y_my_id[s](i, j);
          }
          bit_offset += 1;
        }
      }
    }
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    verifier_s1_message_data_.AssignData(lambda_Y_previous_id);
    multipy_hash_verifier->SetReady();
  }
  else if(my_id == 1) {
    //We are S1 so we send lambda_Y_0+lambda_Y_1 to S2 and lambda_Y_0+lambda_Y_1 to S0
    // Both values already written to lambda_Y_0
    {
      auto payload = SerializeMatrices(lambda_Y_previous_id);
      auto message = 
        communication::BuildMessage(kSwiftBitAOnline, gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
    }
    
    {
      auto payload = SerializeMatrices(lambda_Y_previous_id);
      auto message = 
        communication::BuildMessage(kSwiftBitAOnline, gate_id_, payload);
      communication_layer.SendMessage(0, message.Release());
    }
  } else if(my_id == 2) {
    //We are S2 so we send lambda_Y_2 to S1, which is lambda_Y_my_id
    {
      auto payload = SerializeMatrices(lambda_Y_my_id);
      auto message = 
        communication::BuildMessage(kSwiftBitAOnline, gate_id_, payload);
      communication_layer.SendMessage(1, message.Release());
    }
  } else {
    assert(false);
  }
  
  {
    auto message = bit_a_future_online_.get();
    auto payload = communication::GetMessage(message.data())->payload();
    std::vector<matrix<T>> lambda_Y_missing_id = 
      CreateMatrices<T>(u, v, number_of_simd_values);
    DeserializeMatrices(
      lambda_Y_missing_id, std::span<uint8_t const>{payload->Data(), payload->size()});
    
    {
      size_t bit_offset = 0;
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        for(size_t i = 0; i != u; ++i) {
          for(size_t j = 0; j != v; ++j) {
            if (my_id == 0) { // Got Y0+Y1, have Y2
              out_value_matrices[s](i, j) = 
                bit_matrix_values[bit_offset] + lambda_Y_missing_id[s](i, j) + lambda_Y_previous_id[s](i, j);
            } else if (my_id == 1) { // Got Y2, have Y0+Y1 (in prev)
              out_value_matrices[s](i, j) = 
                bit_matrix_values[bit_offset] + lambda_Y_missing_id[s](i, j) + lambda_Y_previous_id[s](i, j);
            } else if (my_id == 2) { // Got Y0+Y1, have Y2
              out_value_matrices[s](i, j) = 
                bit_matrix_values[bit_offset] + lambda_Y_missing_id[s](i, j) + lambda_Y_my_id[s](i, j);
            } else {
              assert(false);
            }
            bit_offset += 1;
          }
        }
      }
    }

    if (my_id == 1) {
      verifier_received_hash_data_.AssignData(lambda_Y_missing_id);
      multipy_hash_verifier->SetReady();
    }
  }
}

template class SociumBitAGate<std::uint8_t>;
template class SociumBitAGate<std::uint16_t>;
template class SociumBitAGate<std::uint32_t>;
template class SociumBitAGate<std::uint64_t>;


template<typename T>
MsbGate<T>::MsbGate(MatrixWirePointer<T> const& matrix_wire)
: Base(matrix_wire->GetBackend()) {
  using communication::MessageType::kSwiftMsb;
  parent_ = {matrix_wire};
  size_t const u = matrix_wire->GetMutableLambdaMyIdMatrices()[0].size1();
  size_t const v = matrix_wire->GetMutableLambdaPreviousIdMatrices()[0].size2();
  size_t const number_of_simd_values = matrix_wire->GetNumberOfSimdValues();
  
  auto& communication_layer = GetCommunicationLayer();
  uint64_t const my_id = communication_layer.GetMyId();
  size_t const number_of_wires = sizeof(T) * CHAR_BIT;
  size_t const number_of_bits = u * v * number_of_simd_values; 
  
  std::vector<swift::BooleanWirePointer> S_, T_;
  A_.reserve(number_of_wires);
  B_.reserve(number_of_wires);
  C_.reserve(number_of_wires);
  S_.reserve(number_of_wires);
  T_.reserve(number_of_wires);

  for(size_t s = 0; s != number_of_wires; ++s) {
    A_.emplace_back(
      std::make_shared<swift::BooleanWire>(
        backend_,
        BitVector<>(number_of_bits, false), 
        BitVector<>(number_of_bits, false), 
        BitVector<>(number_of_bits, false)));
    B_.emplace_back(
      std::make_shared<swift::BooleanWire>(
        backend_,
        BitVector<>(number_of_bits, false), 
        BitVector<>(number_of_bits, false), 
        BitVector<>(number_of_bits, false)));
    C_.emplace_back(
      std::make_shared<swift::BooleanWire>(
        backend_,
        BitVector<>(number_of_bits, false), 
        BitVector<>(number_of_bits, false), 
        BitVector<>(number_of_bits, false)));
    
    //Build Circuit for S_k
    auto xor_gate_0 = backend_.GetRegister()->EmplaceGate<XorGate>(A_[s], B_[s]);
    auto xor_wire_0 = std::dynamic_pointer_cast<swift::BooleanWire>(xor_gate_0->GetOutputWires()[0]);
    assert(xor_wire_0);
    auto xor_gate_1 = backend_.GetRegister()->EmplaceGate<XorGate>(xor_wire_0, C_[s]);
    auto xor_wire_1 = std::dynamic_pointer_cast<swift::BooleanWire>(xor_gate_1->GetOutputWires()[0]);
    assert(xor_wire_1);
    S_.emplace_back(xor_wire_1);
    
    //Build Circuit for T_k
    //A[s] ^ B[s] is already calculated as xor_gate_0
    auto xor_gate_2 = backend_.GetRegister()->EmplaceGate<XorGate>(A_[s], C_[s]);
    auto xor_wire_2 = std::dynamic_pointer_cast<swift::BooleanWire>(xor_gate_2->GetOutputWires()[0]);
    assert(xor_wire_2);
    auto and_gate_0 = backend_.GetRegister()->EmplaceGate<AndGate>(xor_wire_0, xor_wire_2);
    auto and_wire_0 = std::dynamic_pointer_cast<swift::BooleanWire>(and_gate_0->GetOutputWires()[0]);
    assert(and_wire_0);
    auto xor_gate_3 = backend_.GetRegister()->EmplaceGate<XorGate>(A_[s], and_wire_0);
    auto xor_wire_3 = std::dynamic_pointer_cast<swift::BooleanWire>(xor_gate_3->GetOutputWires()[0]);
    assert(xor_wire_3);
    T_.emplace_back(xor_wire_3);
  }
  PPA_ = swift::MsbAdd(S_, T_);
  
  assert(number_of_bits == PPA_->GetValues().GetSize());
  assert(number_of_bits == PPA_->GetLambdasMyId().GetSize());
  assert(number_of_bits == PPA_->GetLambdasPreviousId().GetSize());
  output_wires_ =
    {GetRegister().template EmplaceWire<swift::BitMatrixWire>(
       backend_, PPA_->GetValues(), PPA_->GetLambdasMyId(), 
       PPA_->GetLambdasPreviousId(), u, v, number_of_simd_values)};

  if(my_id == 0) {
    auto& message_manager = communication_layer.GetMessageManager();
    msb_future_ = message_manager.RegisterReceive(1, kSwiftMsb, gate_id_);
  }
  
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  if(my_id == 0) {
    //S0 will receive a hash from S2
    verifier_data_ = 
      multipy_hash_verifier->ReserveHashCheck(
        number_of_simd_values * sizeof(T), 2);
  } else if(my_id == 2) {
    //S2 will send a hash to S0, so reserve that memory
    verifier_data_ =
      multipy_hash_verifier->ReserveHashMessage(
        number_of_simd_values * sizeof(T), 0);
      
  }
}


template<typename T>
void MsbGate<T>::EvaluateSetup() {
  using boost::numeric::ublas::matrix;
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  auto matrix_in_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_[0]);
  assert(matrix_in_wire);
  auto const& matrix_in_lambdas_my_id = 
    matrix_in_wire->GetMutableLambdaMyIdMatrices();
  auto const& matrix_in_lambdas_previous_id = 
    matrix_in_wire->GetMutableLambdaPreviousIdMatrices();
  auto out_wire = std::dynamic_pointer_cast<swift::BitMatrixWire>(output_wires_[0]);
  assert(out_wire);

  matrix_in_wire->GetSetupReadyCondition()->Wait();
  size_t const u = matrix_in_lambdas_my_id[0].size1();
  size_t const v = matrix_in_lambdas_my_id[0].size2();
  size_t const number_of_simd_values = matrix_in_wire->GetNumberOfSimdValues();
  size_t const number_of_wires = sizeof(T) * CHAR_BIT;
  size_t const number_of_bits = u * v * number_of_simd_values;
  size_t const random_bytes = BitsToBytes(number_of_bits) * number_of_wires;
  
  primitives::SharingRandomnessGenerator* rng_1 = nullptr;
  if(my_id == 1) {
    rng_1 = &(GetBaseProvider().GetMyRandomnessGenerator(2));
  } else if(my_id == 2) {
    rng_1 = &(GetBaseProvider().GetTheirRandomnessGenerator(1));
  }
  auto& rng_0_2 = GetBaseProvider().GetGlobalRandomnessGenerator();
  
  std::vector<uint8_t> randoms_1;
  if(rng_1 != nullptr) {
    randoms_1 = rng_1->template GetUnsigned<uint8_t>(gate_id_, random_bytes);
  }
  std::vector<uint8_t> randoms_0_2 = 
    rng_0_2.template GetUnsigned<uint8_t>(gate_id_, 2 * random_bytes);
    
  for(size_t k = 0; k != number_of_wires; ++k) {
    auto AssignBitMatrix = 
      [&](BitVector<>& target, std::vector<matrix<T>> const& matrices) {
        assert(matrices.size() == number_of_simd_values);
        assert(matrices[0].size1() == u);
        assert(matrices[0].size2() == v);
        assert(target.GetSize() == number_of_bits);
        size_t index = 0;
        for(size_t s = 0; s != number_of_simd_values; ++s) {
          for(size_t i = 0; i != u; ++i) {
            for(size_t j = 0; j != v; ++j, ++index) {
              target.Set((matrices[s](i, j) >> k) & 0x1, index);
            }
          }
        }
        assert(index == number_of_bits);
      };
    auto& A_k_lambdas_my_id = A_[k]->GetMutableLambdasMyId();
    auto& A_k_lambdas_previous_id = A_[k]->GetMutableLambdasPreviousId();
    auto& B_k_lambdas_my_id = B_[k]->GetMutableLambdasMyId();
    auto& B_k_lambdas_previous_id = B_[k]->GetMutableLambdasPreviousId();
    auto& C_k_lambdas_my_id = C_[k]->GetMutableLambdasMyId();
    auto& C_k_lambdas_previous_id = C_[k]->GetMutableLambdasPreviousId();
    auto& C_k_values = C_[k]->GetMutableValues();
    uint8_t const* const rng_0_pointer = 
      randoms_0_2.data() + k * BitsToBytes(number_of_bits);
    uint8_t const* const rng_2_pointer = 
      randoms_0_2.data() + random_bytes + k * BitsToBytes(number_of_bits);
    BitVector<> lambda_c_k_0(rng_0_pointer, number_of_bits);
    BitVector<> lambda_c_k_2(rng_2_pointer, number_of_bits);
    switch(my_id) {
      case 0: {
        assert(rng_1 == nullptr);
        AssignBitMatrix(A_k_lambdas_my_id, matrix_in_lambdas_my_id);
        //lambda_A_k_2 and value_A_k_0 are already set to 0
        AssignBitMatrix(B_k_lambdas_previous_id, matrix_in_lambdas_previous_id);
        //lambda_B_k_0, and value_B_k_0 are already set to 0
        C_k_lambdas_my_id = lambda_c_k_0;
        C_k_lambdas_previous_id = lambda_c_k_2;
        //We do not have lambda_c_k_1 so we do not set value_C_k
        break;
      }
      case 1: {
        assert(rng_1 != nullptr);
        uint8_t const* const rng_1_pointer = 
          randoms_1.data() + k * BitsToBytes(number_of_bits);
        BitVector<> lambda_c_k_1(rng_1_pointer, number_of_bits);
        //matrix_in_lambdas_previous_id is lambda_x_0
        
        AssignBitMatrix(A_k_lambdas_previous_id, matrix_in_lambdas_previous_id);
        //lambda_A_k_1 and value_A_k_1 are already set to 0
        //lambda_B_k_0, lambda_B_k_1 and value_B_k_1 are already set to 0
        C_k_lambdas_previous_id = lambda_c_k_0;
        C_k_lambdas_my_id = lambda_c_k_1;
        //We XOR beforehand
        C_k_values = lambda_c_k_0;
        C_k_values ^= lambda_c_k_1;
        C_k_values ^= lambda_c_k_2;
        break;
      }
      case 2: {
        assert(rng_1 != nullptr);
        uint8_t const* const rng_1_pointer = 
          randoms_1.data() + k * BitsToBytes(number_of_bits);
        BitVector<> lambda_c_k_1(rng_1_pointer, number_of_bits);
        //matrix_in_lambdas_previous_id is lambda_x_0
        
        //lambda_A_k_1, lambda_A_k_2 and value_A_k_1 are already set to 0
        //lambda_B_k_1 and value_B_k_2 are already set to 0
        AssignBitMatrix(B_k_lambdas_my_id, matrix_in_lambdas_my_id);
        C_k_lambdas_previous_id = lambda_c_k_1;
        C_k_lambdas_my_id = lambda_c_k_2;
        //We XOR beforehand
        C_k_values = lambda_c_k_0;
        C_k_values ^= lambda_c_k_1;
        C_k_values ^= lambda_c_k_2;
        break;
      }
    }
    A_[k]->SetSetupIsReady();
    B_[k]->SetSetupIsReady();
    C_[k]->SetSetupIsReady();
  }
  
  PPA_->GetSetupReadyCondition()->Wait();
  out_wire->GetMutableLambdasMyId() = 
    std::move(PPA_->GetMutableLambdasMyId());
  out_wire->GetMutableLambdasPreviousId() = 
    std::move(PPA_->GetMutableLambdasPreviousId());
  //We immediately invert the lambdas of the wire, since we only use msb gate in ReLU
  if(my_id != 1) {
    out_wire->GetMutableLambdasMyId().Invert();
  }
  out_wire->SetSetupIsReady();
}

template<typename T>
void MsbGate<T>::EvaluateOnline() {
  using boost::numeric::ublas::matrix;
  using communication::MessageType::kSwiftMsb;
  WaitSetup();
  assert(setup_is_ready_);
  
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  
  auto matrix_in_wire = std::dynamic_pointer_cast<MatrixWire<T>>(parent_[0]);
  assert(matrix_in_wire);
  auto out_wire = std::dynamic_pointer_cast<swift::BitMatrixWire>(output_wires_[0]);
  assert(out_wire);
  auto const& matrix_in_lambdas_my_id = 
    matrix_in_wire->GetMutableLambdaMyIdMatrices();
  auto const& matrix_in_lambdas_previous_id = 
    matrix_in_wire->GetMutableLambdaPreviousIdMatrices();
  auto const& matrix_in_values = matrix_in_wire->GetMutableValueMatrices();

  size_t const u = matrix_in_lambdas_my_id[0].size1();
  size_t const v = matrix_in_lambdas_my_id[0].size2();
  size_t const number_of_simd_values = matrix_in_wire->GetNumberOfSimdValues();
  size_t const number_of_wires = sizeof(T) * CHAR_BIT;
  size_t const number_of_bits = u * v * number_of_simd_values;
  matrix_in_wire->GetIsReadyCondition().Wait();
  
  std::vector<uint8_t> payload;
  if(my_id != 0) {
    payload.reserve(BitsToBytes(number_of_bits) * number_of_wires);
  }
  for(size_t k = 0; k != number_of_wires; ++k) {
    auto XorValuePlusLambda = 
      [&](BitVector<>& target, 
          std::vector<matrix<T>> const& lambda_matrices, 
          std::vector<matrix<T>> const& value_matrices) {
        assert(lambda_matrices.size() == number_of_simd_values);
        assert(lambda_matrices[0].size1() == u);
        assert(lambda_matrices[0].size2() == v);
        assert(value_matrices.size() == number_of_simd_values);
        assert(value_matrices[0].size1() == u);
        assert(value_matrices[0].size2() == v);
        assert(target.GetSize() == number_of_bits);
        size_t index = 0;
        for(size_t s = 0; s != number_of_simd_values; ++s) {
          for(size_t i = 0; i != u; ++i) {
            for(size_t j = 0; j != v; ++j, ++index) {
              target.Set(
                (((lambda_matrices[s](i, j) + value_matrices[s](i, j)) >> k) & 0x1) 
                ^ target.Get(index), index);
            }
          }
        }
        assert(index == number_of_bits);
      };
    //lambda_c_k is already in value_c_k
    auto& C_k_values = C_[k]->GetMutableValues();
    switch(my_id) {
      case 0: {
        break;
      }
      case 1: {
        XorValuePlusLambda(C_k_values, matrix_in_lambdas_my_id, matrix_in_values);
        //Since m_A_k_1 and m_B_k_1 are 0 T_k_1 is also 0
        for(std::byte b : C_k_values.GetData())
          payload.emplace_back(uint8_t(b));
        A_[k]->SetOnlineFinished();
        B_[k]->SetOnlineFinished();
        C_[k]->SetOnlineFinished();
        break;
      }
      case 2: {
        XorValuePlusLambda(C_k_values, matrix_in_lambdas_previous_id, matrix_in_values);
        //Since m_A_k_2 and m_B_k_2 are 0 T_k_2 is also 0
        for(std::byte b : C_k_values.GetData())
          payload.emplace_back(uint8_t(b));
        A_[k]->SetOnlineFinished();
        B_[k]->SetOnlineFinished();
        C_[k]->SetOnlineFinished();
        break;
      }
    }
  }
  
  auto multipy_hash_verifier = backend_.GetSwiftMultiplyHashVerifier();
  switch(my_id) {
    case 0: {
      auto message = msb_future_.get();
      auto payload = communication::GetMessage(message.data())->payload();
      for(size_t k = 0; k != number_of_wires; ++k) {
        auto& C_k_values = C_[k]->GetMutableValues();
        C_k_values = BitVector<>(payload->Data() + k * BitsToBytes(number_of_bits), number_of_bits);
        A_[k]->SetOnlineFinished();
        B_[k]->SetOnlineFinished();
        C_[k]->SetOnlineFinished();
      }
      std::span<uint8_t const> spn(payload->Data(), payload->size());
      verifier_data_.AssignData(spn);
      multipy_hash_verifier->SetReady();
      break;
    } case 1: {
      auto message = 
        communication::BuildMessage(kSwiftMsb, gate_id_, payload);
      communication_layer.SendMessage(0, message.Release());
      break;
    } case 2: {
      verifier_data_.AssignData(payload);
      multipy_hash_verifier->SetReady();
      break;
    }
  }
    
  PPA_->GetIsReadyCondition().Wait();
  out_wire->GetMutableValues() = 
    std::move(PPA_->GetMutableValues());
}

template class MsbGate<std::uint8_t>;
template class MsbGate<std::uint16_t>;
template class MsbGate<std::uint32_t>;
template class MsbGate<std::uint64_t>;

template<typename T>
SociumMsbGate<T>::SociumMsbGate(MatrixWirePointer<T> const& matrix_wire)
: Base(matrix_wire->GetBackend()) {
  using communication::MessageType::kSwiftMsb;
  parent_ = {matrix_wire};
  size_t const u = matrix_wire->GetMutableLambdaMyIdMatrices()[0].size1();
  size_t const v = matrix_wire->GetMutableLambdaPreviousIdMatrices()[0].size2();
  size_t const number_of_simd_values = matrix_wire->GetNumberOfSimdValues();
  
  auto& communication_layer = GetCommunicationLayer();
  uint64_t const my_id = communication_layer.GetMyId();
  size_t const number_of_wires = sizeof(T) * CHAR_BIT;
  size_t const number_of_bits = u * v * number_of_simd_values; 
  
  std::vector<swift::BooleanWirePointer> S_, T_;
  A_.reserve(number_of_wires);
  B_.reserve(number_of_wires);
  C_.reserve(number_of_wires);
  S_.reserve(number_of_wires);
  T_.reserve(number_of_wires);

  for(size_t s = 0; s != number_of_wires; ++s) {
    A_.emplace_back(
      std::make_shared<swift::BooleanWire>(
        backend_,
        BitVector<>(number_of_bits, false), 
        BitVector<>(number_of_bits, false), 
        BitVector<>(number_of_bits, false)));
    B_.emplace_back(
      std::make_shared<swift::BooleanWire>(
        backend_,
        BitVector<>(number_of_bits, false), 
        BitVector<>(number_of_bits, false), 
        BitVector<>(number_of_bits, false)));
    C_.emplace_back(
      std::make_shared<swift::BooleanWire>(
        backend_,
        BitVector<>(number_of_bits, false), 
        BitVector<>(number_of_bits, false), 
        BitVector<>(number_of_bits, false)));
    
    //Build Circuit for S_k
    auto xor_gate_0 = backend_.GetRegister()->EmplaceGate<XorGate>(A_[s], B_[s]);
    auto xor_wire_0 = std::dynamic_pointer_cast<swift::BooleanWire>(xor_gate_0->GetOutputWires()[0]);
    assert(xor_wire_0);
    auto xor_gate_1 = backend_.GetRegister()->EmplaceGate<XorGate>(xor_wire_0, C_[s]);
    auto xor_wire_1 = std::dynamic_pointer_cast<swift::BooleanWire>(xor_gate_1->GetOutputWires()[0]);
    assert(xor_wire_1);
    S_.emplace_back(xor_wire_1);
    
    //Build Circuit for T_k
    //A[s] ^ B[s] is already calculated as xor_gate_0
    auto xor_gate_2 = backend_.GetRegister()->EmplaceGate<XorGate>(A_[s], C_[s]);
    auto xor_wire_2 = std::dynamic_pointer_cast<swift::BooleanWire>(xor_gate_2->GetOutputWires()[0]);
    assert(xor_wire_2);
    auto and_gate_0 = backend_.GetRegister()->EmplaceGate<SociumAndGate>(xor_wire_0, xor_wire_2);
    auto and_wire_0 = std::dynamic_pointer_cast<swift::BooleanWire>(and_gate_0->GetOutputWires()[0]);
    assert(and_wire_0);
    auto xor_gate_3 = backend_.GetRegister()->EmplaceGate<XorGate>(A_[s], and_wire_0);
    auto xor_wire_3 = std::dynamic_pointer_cast<swift::BooleanWire>(xor_gate_3->GetOutputWires()[0]);
    assert(xor_wire_3);
    T_.emplace_back(xor_wire_3);
  }
  PPA_ = swift::SociumMsbAdd(S_, T_);
  
  assert(number_of_bits == PPA_->GetValues().GetSize());
  assert(number_of_bits == PPA_->GetLambdasMyId().GetSize());
  assert(number_of_bits == PPA_->GetLambdasPreviousId().GetSize());
  output_wires_ =
    {GetRegister().template EmplaceWire<swift::BitMatrixWire>(
       backend_, PPA_->GetValues(), PPA_->GetLambdasMyId(), 
       PPA_->GetLambdasPreviousId(), u, v, number_of_simd_values)};
  
  if(my_id == 0) {
    auto& message_manager = communication_layer.GetMessageManager();
    msb_future_ = message_manager.RegisterReceive(1, kSwiftMsb, gate_id_);
  }
}


template<typename T>
void SociumMsbGate<T>::EvaluateSetup() {
  using boost::numeric::ublas::matrix;
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  auto matrix_in_wire = std::dynamic_pointer_cast<swift::MatrixWire<T>>(parent_[0]);
  assert(matrix_in_wire);
  auto const& matrix_in_lambdas_my_id = 
    matrix_in_wire->GetMutableLambdaMyIdMatrices();
  auto const& matrix_in_lambdas_previous_id = 
    matrix_in_wire->GetMutableLambdaPreviousIdMatrices();
  auto out_wire = std::dynamic_pointer_cast<swift::BitMatrixWire>(output_wires_[0]);
  assert(out_wire);

  matrix_in_wire->GetSetupReadyCondition()->Wait();
  size_t const u = matrix_in_lambdas_my_id[0].size1();
  size_t const v = matrix_in_lambdas_my_id[0].size2();
  size_t const number_of_simd_values = matrix_in_wire->GetNumberOfSimdValues();
  size_t const number_of_wires = sizeof(T) * CHAR_BIT;
  size_t const number_of_bits = u * v * number_of_simd_values;
  size_t const random_bytes = BitsToBytes(number_of_bits) * number_of_wires;
  
  primitives::SharingRandomnessGenerator* rng_1 = nullptr;
  if(my_id == 1) {
    rng_1 = &(GetBaseProvider().GetMyRandomnessGenerator(2));
  } else if(my_id == 2) {
    rng_1 = &(GetBaseProvider().GetTheirRandomnessGenerator(1));
  }
  auto& rng_0_2 = GetBaseProvider().GetGlobalRandomnessGenerator();
  
  std::vector<uint8_t> randoms_1;
  if(rng_1 != nullptr) {
    randoms_1 = rng_1->template GetUnsigned<uint8_t>(gate_id_, random_bytes);
  }
  std::vector<uint8_t> randoms_0_2 = 
    rng_0_2.template GetUnsigned<uint8_t>(gate_id_, 2 * random_bytes);
    
  for(size_t k = 0; k != number_of_wires; ++k) {
    auto AssignBitMatrix = 
      [&](BitVector<>& target, std::vector<matrix<T>> const& matrices) {
        assert(matrices.size() == number_of_simd_values);
        assert(matrices[0].size1() == u);
        assert(matrices[0].size2() == v);
        assert(target.GetSize() == number_of_bits);
        size_t index = 0;
        for(size_t s = 0; s != number_of_simd_values; ++s) {
          for(size_t i = 0; i != u; ++i) {
            for(size_t j = 0; j != v; ++j, ++index) {
              target.Set((matrices[s](i, j) >> k) & 0x1, index);
            }
          }
        }
        assert(index == number_of_bits);
      };
    auto& A_k_lambdas_my_id = A_[k]->GetMutableLambdasMyId();
    auto& A_k_lambdas_previous_id = A_[k]->GetMutableLambdasPreviousId();
    auto& B_k_lambdas_my_id = B_[k]->GetMutableLambdasMyId();
    auto& B_k_lambdas_previous_id = B_[k]->GetMutableLambdasPreviousId();
    auto& C_k_lambdas_my_id = C_[k]->GetMutableLambdasMyId();
    auto& C_k_lambdas_previous_id = C_[k]->GetMutableLambdasPreviousId();
    auto& C_k_values = C_[k]->GetMutableValues();
    uint8_t const* const rng_0_pointer = 
      randoms_0_2.data() + k * BitsToBytes(number_of_bits);
    uint8_t const* const rng_2_pointer = 
      randoms_0_2.data() + random_bytes + k * BitsToBytes(number_of_bits);
    BitVector<> lambda_c_k_0(rng_0_pointer, number_of_bits);
    BitVector<> lambda_c_k_2(rng_2_pointer, number_of_bits);
    switch(my_id) {
      case 0: {
        assert(rng_1 == nullptr);
        AssignBitMatrix(A_k_lambdas_my_id, matrix_in_lambdas_my_id);
        //lambda_A_k_2 and value_A_k_0 are already set to 0
        AssignBitMatrix(B_k_lambdas_previous_id, matrix_in_lambdas_previous_id);
        //lambda_B_k_0, and value_B_k_0 are already set to 0
        C_k_lambdas_my_id = lambda_c_k_0;
        C_k_lambdas_previous_id = lambda_c_k_2;
        //We do not have lambda_c_k_1 so we do not set value_C_k
        break;
      }
      case 1: {
        assert(rng_1 != nullptr);
        uint8_t const* const rng_1_pointer = 
          randoms_1.data() + k * BitsToBytes(number_of_bits);
        BitVector<> lambda_c_k_1(rng_1_pointer, number_of_bits);
        //matrix_in_lambdas_previous_id is lambda_x_0
        
        AssignBitMatrix(A_k_lambdas_previous_id, matrix_in_lambdas_previous_id);
        //lambda_A_k_1 and value_A_k_1 are already set to 0
        //lambda_B_k_0, lambda_B_k_1 and value_B_k_1 are already set to 0
        C_k_lambdas_previous_id = lambda_c_k_0;
        C_k_lambdas_my_id = lambda_c_k_1;
        //We XOR beforehand
        C_k_values = lambda_c_k_0;
        C_k_values ^= lambda_c_k_1;
        C_k_values ^= lambda_c_k_2;
        break;
      }
      case 2: {
        assert(rng_1 != nullptr);
        uint8_t const* const rng_1_pointer = 
          randoms_1.data() + k * BitsToBytes(number_of_bits);
        BitVector<> lambda_c_k_1(rng_1_pointer, number_of_bits);
        //matrix_in_lambdas_previous_id is lambda_x_0
        
        //lambda_A_k_1, lambda_A_k_2 and value_A_k_1 are already set to 0
        //lambda_B_k_1 and value_B_k_2 are already set to 0
        AssignBitMatrix(B_k_lambdas_my_id, matrix_in_lambdas_my_id);
        C_k_lambdas_previous_id = lambda_c_k_1;
        C_k_lambdas_my_id = lambda_c_k_2;
        //We XOR beforehand
        C_k_values = lambda_c_k_0;
        C_k_values ^= lambda_c_k_1;
        C_k_values ^= lambda_c_k_2;
        break;
      }
    }
    A_[k]->SetSetupIsReady();
    B_[k]->SetSetupIsReady();
    C_[k]->SetSetupIsReady();
  }
  
  PPA_->GetSetupReadyCondition()->Wait();
  out_wire->GetMutableLambdasMyId() = 
    std::move(PPA_->GetMutableLambdasMyId());
  out_wire->GetMutableLambdasPreviousId() = 
    std::move(PPA_->GetMutableLambdasPreviousId());
  //We immediately invert the lambdas of the wire, since we only use msb gate in ReLU
  if(my_id != 1) {
    out_wire->GetMutableLambdasMyId().Invert();
  }
  out_wire->SetSetupIsReady();
}

template<typename T>
void SociumMsbGate<T>::EvaluateOnline() {
  using boost::numeric::ublas::matrix;
  using communication::MessageType::kSwiftMsb;
  WaitSetup();
  assert(setup_is_ready_);
  
  auto& communication_layer = GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  
  auto matrix_in_wire = std::dynamic_pointer_cast<MatrixWire<T>>(parent_[0]);
  assert(matrix_in_wire);
  auto out_wire = std::dynamic_pointer_cast<swift::BitMatrixWire>(output_wires_[0]);
  assert(out_wire);
  auto const& matrix_in_lambdas_my_id = 
    matrix_in_wire->GetMutableLambdaMyIdMatrices();
  auto const& matrix_in_lambdas_previous_id = 
    matrix_in_wire->GetMutableLambdaPreviousIdMatrices();
  auto const& matrix_in_values = matrix_in_wire->GetMutableValueMatrices();

  size_t const u = matrix_in_lambdas_my_id[0].size1();
  size_t const v = matrix_in_lambdas_my_id[0].size2();
  size_t const number_of_simd_values = matrix_in_wire->GetNumberOfSimdValues();
  size_t const number_of_wires = sizeof(T) * CHAR_BIT;
  size_t const number_of_bits = u * v * number_of_simd_values;
  matrix_in_wire->GetIsReadyCondition().Wait();
  
  std::vector<uint8_t> payload;
  if(my_id == 1) {
    payload.reserve(BitsToBytes(number_of_bits) * number_of_wires);
  }
  for(size_t k = 0; k != number_of_wires; ++k) {
    auto XorValuePlusLambda = 
      [&](BitVector<>& target, 
          std::vector<matrix<T>> const& lambda_matrices, 
          std::vector<matrix<T>> const& value_matrices) {
        assert(lambda_matrices.size() == number_of_simd_values);
        assert(lambda_matrices[0].size1() == u);
        assert(lambda_matrices[0].size2() == v);
        assert(value_matrices.size() == number_of_simd_values);
        assert(value_matrices[0].size1() == u);
        assert(value_matrices[0].size2() == v);
        assert(target.GetSize() == number_of_bits);
        size_t index = 0;
        for(size_t s = 0; s != number_of_simd_values; ++s) {
          for(size_t i = 0; i != u; ++i) {
            for(size_t j = 0; j != v; ++j, ++index) {
              target.Set(
                (((lambda_matrices[s](i, j) + value_matrices[s](i, j)) >> k) & 0x1) 
                ^ target.Get(index), index);
            }
          }
        }
        assert(index == number_of_bits);
      };
    //lambda_c_k is already in S_k_values
    auto& C_k_values = C_[k]->GetMutableValues();
    switch(my_id) {
      case 0: {
        break;
      }
      case 1: {
        XorValuePlusLambda(C_k_values, matrix_in_lambdas_my_id, matrix_in_values);
        //Since m_A_k_1 and m_B_k_1 are 0 T_k_1 is also 0
        for(std::byte b : C_k_values.GetData())
          payload.emplace_back(uint8_t(b));
        A_[k]->SetOnlineFinished();
        B_[k]->SetOnlineFinished();
        C_[k]->SetOnlineFinished();
        break;
      }
      case 2: {
        XorValuePlusLambda(C_k_values, matrix_in_lambdas_previous_id, matrix_in_values);
        //Since m_A_k_2 and m_B_k_2 are 0 T_k_2 is also 0
        for(std::byte b : C_k_values.GetData())
          payload.emplace_back(uint8_t(b));
        A_[k]->SetOnlineFinished();
        B_[k]->SetOnlineFinished();
        C_[k]->SetOnlineFinished();
        break;
      }
    }
  }
  
  if (my_id == 0) {
    auto message = msb_future_.get();
      auto payload = communication::GetMessage(message.data())->payload();
      for(size_t k = 0; k != number_of_wires; ++k) {
        auto& C_k_values = C_[k]->GetMutableValues();
        C_k_values = BitVector<>(payload->Data() + k * BitsToBytes(number_of_bits), number_of_bits);
        A_[k]->SetOnlineFinished();
        B_[k]->SetOnlineFinished();
        C_[k]->SetOnlineFinished();
      }
  } else if (my_id == 1) {
    auto message = 
        communication::BuildMessage(kSwiftMsb, gate_id_, payload);
      communication_layer.SendMessage(0, message.Release());
  }
    
  PPA_->GetIsReadyCondition().Wait();
  out_wire->GetMutableValues() = 
    std::move(PPA_->GetMutableValues());
}

template class SociumMsbGate<std::uint8_t>;
template class SociumMsbGate<std::uint16_t>;
template class SociumMsbGate<std::uint32_t>;
template class SociumMsbGate<std::uint64_t>;

}  // namespace encrypto::motion::proto::swift