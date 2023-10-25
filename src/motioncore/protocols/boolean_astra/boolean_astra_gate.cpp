#include <algorithm>
#include <functional>
#include <mutex>
#include <type_traits>
#include <map>

#include "boolean_astra_gate.h"
#include "boolean_astra_share.h"
#include "boolean_astra_wire.h"
#include "protocols/share_wrapper.h"
#include "communication/message_manager.h"
#include "primitives/sharing_randomness_generator.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "utility/helpers.h"

#include <string>
#include <iostream>

namespace encrypto::motion::proto::boolean_astra {

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

template<typename Allocator>
std::span<const std::uint8_t> ToByteSpan(BitVector<Allocator> const& bit_vector) {
  constexpr size_t kBitVectorInternalSize = 
    sizeof(typename std::decay_t<decltype(bit_vector.GetData())>::value_type);
    
  return std::span<const std::uint8_t>(
           reinterpret_cast<const std::uint8_t*>(bit_vector.GetData().data()),
           bit_vector.GetData().size() * kBitVectorInternalSize);
}

void AssignValues(std::vector<motion::WirePointer>& wires, std::span<const std::uint8_t> s) {
  size_t bitlen = wires.size();
  auto it = s.begin();
  [[maybe_unused]] auto const end_it = s.end();
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    assert(w);
    auto& values = w->GetMutableValues();
    for(std::byte& b : values.GetMutableData()) {
      assert(it != end_it);
      b = std::byte(*it);
      ++it;
    }
  }
  assert(it == end_it);
}

void XorAssignValues(std::vector<motion::WirePointer>& wires, std::span<const std::uint8_t> s) {
  size_t bitlen = wires.size();
  auto it = s.begin();
  [[maybe_unused]] auto const end_it = s.end();
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    assert(w);
    auto& values = w->GetMutableValues();
    for(std::byte& b : values.GetMutableData()) {
      assert(it != end_it);
      b ^= std::byte(*it);
      ++it;
    }
  }
  assert(it == end_it);
}

auto BuildValuesMessage(std::vector<motion::WirePointer> const& wires,
                        int64_t gate_id,
                        communication::MessageType message_type) {
  size_t bitlen = wires.size();
  assert(0 < bitlen);
  std::vector<uint8_t> payload;
  //In most cases the SIMD values will be of equal bitsize
  payload.reserve(bitlen * wires[0]->GetNumberOfSimdValues());
  for(size_t s = 0u; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto const& values = w->GetValues();
    auto byte_span = ToByteSpan(values);
    std::copy(byte_span.begin(), byte_span.end(), std::back_inserter(payload));
  }
  return communication::BuildMessage(message_type, gate_id, std::move(payload));
}

auto BuildLambdas1Message(std::vector<motion::WirePointer> const& wires,
                         int64_t gate_id,
                         communication::MessageType message_type) {
  size_t bitlen = wires.size();
  assert(0 < bitlen);
  std::vector<uint8_t> payload;
  //In most cases the SIMD values will be of equal bitsize
  payload.reserve(bitlen * wires[0]->GetNumberOfSimdValues());
  for(size_t s = 0u; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto const& lambdas = w->GetLambdas1();
    auto byte_span = ToByteSpan(lambdas);
    std::copy(byte_span.begin(), byte_span.end(), std::back_inserter(payload));
  }
  return communication::BuildMessage(message_type, gate_id, std::move(payload));
}

void SendLambdas1(std::vector<motion::WirePointer> const& wires,
                 size_t target_id,
                 int64_t gate_id,
                 communication::CommunicationLayer& communication_layer, 
                 communication::MessageType message_type) {
    auto message = BuildLambdas1Message(wires, gate_id, message_type);
    communication_layer.SendMessage(target_id, message.Release());
}

auto BuildLambdas2Message(std::vector<motion::WirePointer> const& wires,
                         int64_t gate_id,
                         communication::MessageType message_type) {
  size_t bitlen = wires.size();
  assert(0 < bitlen);
  std::vector<uint8_t> payload;
  //In most cases the SIMD values will be of equal bitsize
  payload.reserve(bitlen * wires[0]->GetNumberOfSimdValues());
  for(size_t s = 0u; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto const& lambdas = w->GetLambdas2();
    auto byte_span = ToByteSpan(lambdas);
    std::copy(byte_span.begin(), byte_span.end(), std::back_inserter(payload));
  }
  return communication::BuildMessage(message_type, gate_id, std::move(payload));
}

void SendLambdas2(std::vector<motion::WirePointer> const& wires,
                 size_t target_id,
                 int64_t gate_id,
                 communication::CommunicationLayer& communication_layer, 
                 communication::MessageType message_type) {
    auto message = BuildLambdas2Message(wires, gate_id, message_type);
    communication_layer.SendMessage(target_id, message.Release());
}

void SendValues(std::vector<motion::WirePointer> const& wires,
                size_t target_id,
                int64_t gate_id,
                communication::CommunicationLayer& communication_layer, 
                communication::MessageType message_type) {
    auto message = BuildValuesMessage(wires, gate_id, message_type);
    communication_layer.SendMessage(target_id, message.Release());
}

void BroadcastValues(std::vector<motion::WirePointer> const& wires,
                     int64_t gate_id,
                     communication::CommunicationLayer& communication_layer, 
                     communication::MessageType message_type) {
    auto message = BuildValuesMessage(wires, gate_id, message_type);
    communication_layer.BroadcastMessage(message.Release());
}

void SetLambdas1ToRandom(std::vector<motion::WirePointer>& wires, auto& rng, size_t gate_id) {
  size_t number_of_bits = 0;
  size_t bitlen = wires.size();
  assert(0 < bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto const& lambdas = w->GetLambdas1();
    number_of_bits += lambdas.GetSize();
  }
  assert(0 < number_of_bits);
  BitVector<> randoms = rng.GetBits(gate_id, number_of_bits);
  size_t offset = 0;
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto& lambdas = w->GetMutableLambdas1();
    size_t bitlen = lambdas.GetSize();
    lambdas = randoms.Subset(offset, offset + bitlen);
    offset += bitlen;
  }
  assert(offset == number_of_bits);
}

void SetLambdas2ToRandom(std::vector<motion::WirePointer>& wires, auto& rng, size_t gate_id) {
  size_t number_of_bits = 0;
  size_t bitlen = wires.size();
  assert(0 < bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto const& lambdas = w->GetLambdas2();
    number_of_bits += lambdas.GetSize();
  }
  assert(0 < number_of_bits);
  BitVector<> randoms = rng.GetBits(gate_id, number_of_bits);
  size_t offset = 0;
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto& lambdas = w->GetMutableLambdas2();
    size_t bitlen = lambdas.GetSize();
    lambdas = randoms.Subset(offset, offset + bitlen);
    offset += bitlen;
  }
  assert(offset == number_of_bits);
}

void SetValuesToRandom(std::vector<motion::WirePointer>& wires, auto& rng, size_t gate_id) {

  size_t number_of_bits = 0;
  size_t bitlen = wires.size();
  assert(0 < bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto const& values = w->GetValues();
    number_of_bits += values.GetSize();
  }
  assert(0 < number_of_bits);
  BitVector<> randoms = rng.GetBits(gate_id, number_of_bits);
  size_t offset = 0;
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto& values = w->GetMutableValues();
    size_t bitlen = values.GetSize();
    values = randoms.Subset(offset, offset + bitlen);
    offset += bitlen;
  }
  assert(offset == number_of_bits);
}

void SetLambdas1AndValuesToRandom(std::vector<motion::WirePointer>& wires, auto& rng, size_t gate_id) {
  size_t number_of_bits_lambdas = 0;
  size_t number_of_bits_values = 0;
  size_t bitlen = wires.size();
  assert(0 != bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto const& lambdas = w->GetLambdas1();
    auto const& values = w->GetValues();
    number_of_bits_lambdas += lambdas.GetSize();
    number_of_bits_values += values.GetSize();
  }
  assert(0 < number_of_bits_lambdas);
  assert(0 < number_of_bits_values);
  BitVector<> randoms = rng.GetBits(gate_id, number_of_bits_lambdas + number_of_bits_values);
  size_t offset = 0;
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto& lambdas = w->GetMutableLambdas1();
    size_t bitlen = lambdas.GetSize();
    lambdas = randoms.Subset(offset, offset + bitlen);
    offset += bitlen;
  }
  assert(offset == number_of_bits_lambdas);
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto& values = w->GetMutableValues();
    size_t number_of_simd_values = values.GetSize();
    values = randoms.Subset(offset, offset + number_of_simd_values);
    offset += number_of_simd_values;
  }
  assert(offset == number_of_bits_lambdas + number_of_bits_values);
}

void XorRandom(std::vector<BitVector<>>& bit_vectors, auto& rng, size_t gate_id) {
  size_t number_of_bits = 0;
  for(auto&& bv : bit_vectors) {
    number_of_bits += bv.GetSize();
  }
  assert(number_of_bits > 0);
  BitVector<> randoms = rng.GetBits(gate_id, number_of_bits);
  size_t offset = 0;
  for(auto& bv : bit_vectors) {
    bv ^= randoms.Subset(offset, offset + bv.GetSize());
    offset += bv.GetSize();
  }
  assert(offset == number_of_bits);
}

void XorLambdas1WithRandom(std::vector<motion::WirePointer>& wires, auto& rng, size_t gate_id) {
  size_t number_of_bits = 0;
  size_t bitlen = wires.size();
  assert(0 != bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto const& lambdas = w->GetLambdas1();
    number_of_bits += lambdas.GetSize();
  }
  assert(0 < number_of_bits);
  BitVector<> randoms = rng.GetBits(gate_id, number_of_bits);
  size_t offset = 0;
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto& lambdas = w->GetMutableLambdas1();
    size_t bitlen = lambdas.GetSize();
    lambdas ^= randoms.Subset(offset, offset + bitlen);
    offset += bitlen;
  }
  assert(offset == number_of_bits);
}

void XorLambdas2WithRandom(std::vector<motion::WirePointer>& wires, auto& rng, size_t gate_id) {
  size_t number_of_bits = 0;
  size_t bitlen = wires.size();
  assert(0 != bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto const& lambdas = w->GetLambdas2();
    number_of_bits += lambdas.GetSize();
  }
  assert(0 < number_of_bits);
  BitVector<> randoms = rng.GetBits(gate_id, number_of_bits);
  size_t offset = 0;
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto& lambdas = w->GetMutableLambdas2();
    size_t bitlen = lambdas.GetSize();
    lambdas ^= randoms.Subset(offset, offset + bitlen);
    offset += bitlen;
  }
  assert(offset == number_of_bits);
}

void XorValuesWithRandom(std::vector<motion::WirePointer>& wires, auto& rng, size_t gate_id) {
  size_t number_of_bits = 0;
  size_t bitlen = wires.size();
  assert(0 != bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto const& values = w->GetValues();
    number_of_bits += values.GetSize();
  }
  assert(0 < number_of_bits);
  BitVector<> randoms = rng.GetBits(gate_id, number_of_bits);
  size_t offset = 0;
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto& values = w->GetMutableValues();
    size_t bitlen = values.GetSize();
    values ^= randoms.Subset(offset, offset + bitlen);
    offset += bitlen;
  }
  assert(offset == number_of_bits);
}

void SetSetupReady(std::vector<motion::WirePointer>& wires) {
  for(auto& w : wires) {
    auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(w);
    assert(out_wire);
    out_wire->SetSetupIsReady(); 
  }
}

std::pair<std::vector<std::vector<uint64_t>>, std::vector<BitVector<>>> 
GenerateRandomGammaAbExtendedAndLambdas1(
  std::vector<motion::WirePointer>& wires, auto& rng, size_t gate_id) {
  size_t number_of_bits = 0;
  size_t bitlen = wires.size();
  assert(0 < bitlen);
  std::vector<BitVector<>> random_lambdas;
  random_lambdas.reserve(bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(wires[s]);
    auto const& lambdas = w->GetLambdas1();
    number_of_bits += lambdas.GetSize();
    assert(0 < lambdas.GetSize());
    random_lambdas.emplace_back(lambdas);
  }
  assert(0 < number_of_bits);
  assert(random_lambdas.size() == bitlen);
  //We will generate number_of_bits 64-bit values and number_of_bits 1-bit values
  size_t random_size;
  if(number_of_bits % 64 == 0){
    random_size = number_of_bits + number_of_bits/64;
  } else {
    //We need an additional uint64_t to store the remaining bits
    random_size = number_of_bits + number_of_bits/64 + 1;
  }
  std::vector<uint64_t> randoms = rng.template GetUnsigned<uint64_t>(gate_id, random_size);
  //The offset to get to the part of the input holding the 1 bit values
  size_t const bit_vector_offset = number_of_bits;
  //The iterator to the current 64-bit value
  auto extended_it = randoms.begin();
  //The offset to he current bit in the 1-bit values
  size_t randoms_bit_offset = 0;
  std::vector<std::vector<uint64_t>> gamma_ab_extended;
  gamma_ab_extended.reserve(bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    size_t number_of_simd_values = random_lambdas[s].GetSize();
    for(size_t i = 0; i != number_of_simd_values; ++i, ++randoms_bit_offset) {
      size_t const random_bit_index = bit_vector_offset + randoms_bit_offset/64;
      size_t const shift = i % 64;
      random_lambdas[s].Set(bool((randoms[random_bit_index] >> shift) & 0x1), i);
    }
    gamma_ab_extended.emplace_back(extended_it, extended_it + number_of_simd_values);
    extended_it += number_of_simd_values;
    assert(gamma_ab_extended.size() == s + 1);
    assert(gamma_ab_extended[s].size() == number_of_simd_values);
  }
  assert(number_of_bits == randoms_bit_offset);
  assert(gamma_ab_extended.size() == bitlen);
  assert(randoms.begin() + number_of_bits == extended_it);
  //We delete the 1-bit values in gamma_ab_extend
  return {gamma_ab_extended, random_lambdas};
}

}  // namespace (anonymous)

InputGate::InputGate(std::vector<BitVector<>> input, std::size_t input_owner, Backend& backend)
: Base(backend) {
  input_owner_id_ = input_owner;

  auto my_id = static_cast<std::int64_t>(GetCommunicationLayer().GetMyId());

  size_t bitlen = input.size();
  output_wires_.reserve(bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    //The lambdas will be overwritten later
    output_wires_.emplace_back(
      GetRegister().template EmplaceWire<boolean_astra::Wire>(
        backend_, input[s], input[s], input[s]));
  }

  if (my_id != input_owner_id_ && my_id != 0) {
    input_future_ = GetCommunicationLayer().GetMessageManager().RegisterReceive(
        input_owner_id_, communication::MessageType::kBooleanAstraInputGate, gate_id_);
  }
}

void InputGate::EvaluateSetup() {
  using namespace std::string_literals;
  using std::to_string;
  
  auto my_id = GetCommunicationLayer().GetMyId();
  GetBaseProvider().WaitSetup();

  size_t bitlen = output_wires_.size();
  //Party 0 stores lambda1 and lambda2, Party 1 stores lambda1 and Party 2 stores lambda2
  //The input owner additionally stores mx = x ^ lambda
  switch (input_owner_id_) {
    case 0: {
      switch (my_id) {
        case 0: {
          auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
          auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
          SetLambdas1ToRandom(output_wires_, rng1, gate_id_);
          SetLambdas2ToRandom(output_wires_, rng2, gate_id_);
          for(size_t s = 0; s != bitlen; ++s) {
            auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
            assert(out_wire);
            auto& values = out_wire->GetMutableValues();
            auto const& lambdas1 = out_wire->GetLambdas1();
            auto const& lambdas2 = out_wire->GetLambdas2();
            values ^= lambdas1;
            values ^= lambdas2;
          }
          break;
        }
        case 1: {
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          SetLambdas1ToRandom(output_wires_, rng0, gate_id_);
          break;
        }
        case 2: {
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          SetLambdas2ToRandom(output_wires_, rng0, gate_id_);
          break;
        }
      }
      break;
    }
    case 1: {
      switch (my_id) {
        case 0: {
          auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          SetLambdas1ToRandom(output_wires_, rng1, gate_id_);
          SetLambdas2ToRandom(output_wires_, rng_global, gate_id_);
          break;
        }
        case 1: {
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          SetLambdas1ToRandom(output_wires_, rng0, gate_id_);
          SetLambdas2ToRandom(output_wires_, rng_global, gate_id_);
          for(size_t s = 0; s != bitlen; ++s) {
            auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
            assert(out_wire);
            auto& values = out_wire->GetMutableValues();
            auto const& lambdas1 = out_wire->GetLambdas1();
            auto const& lambdas2 = out_wire->GetLambdas2();
            values ^= lambdas1;
            values ^= lambdas2;
          }
          break;
        }
        case 2: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          SetLambdas2ToRandom(output_wires_, rng_global, gate_id_);
          break;
        }
      }
      break;
    }
    case 2: {
      switch (my_id) {
        case 0: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
          SetLambdas1ToRandom(output_wires_, rng_global, gate_id_);
          SetLambdas2ToRandom(output_wires_, rng2, gate_id_);
          break;
        }
        case 1: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          SetLambdas1ToRandom(output_wires_, rng_global, gate_id_);
          break;
        }
        case 2: {
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          SetLambdas1ToRandom(output_wires_, rng_global, gate_id_);
          SetLambdas2ToRandom(output_wires_, rng0, gate_id_);
          for(size_t s = 0; s != bitlen; ++s) {
            auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
            assert(out_wire);
            auto& values = out_wire->GetMutableValues();
            auto const& lambdas1 = out_wire->GetLambdas1();
            auto const& lambdas2 = out_wire->GetLambdas2();
            values ^= lambdas1;
            values ^= lambdas2;
          }
          break;
        }
      }
      break;
    }
  }
  SetSetupReady(output_wires_);
}

void InputGate::EvaluateOnline() {
  using namespace std::string_literals;
  using std::to_string;
  using communication::MessageType::kBooleanAstraInputGate;
  WaitSetup();
  assert(setup_is_ready_);

  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  
  if(std::size_t(input_owner_id_) == my_id) {
    //Send mx = x ^ lambda
    if (my_id == 0) {
      BroadcastValues(output_wires_, gate_id_, communication_layer, kBooleanAstraInputGate);
    } else if (my_id == 1) {
      SendValues(output_wires_, 2, gate_id_, communication_layer, kBooleanAstraInputGate);
    } else if (my_id == 2) {
      SendValues(output_wires_, 1, gate_id_, communication_layer, kBooleanAstraInputGate);
    }
  } else if(my_id != 0) {
    //Receive mx = x ^ lambda from input owner
    auto input_message = input_future_.get();
    auto payload = communication::GetMessage(input_message.data())->payload();
    AssignValues(output_wires_, {payload->Data(), payload->size()});
  }
}

boolean_astra::SharePointer InputGate::GetOutputAsBooleanAstraShare() {
  return std::make_shared<boolean_astra::Share>(output_wires_);
}

OutputGate::OutputGate(ShareWrapper const& parent, std::size_t output_owner)
: Base(parent->GetBackend()) {
  if (parent->GetProtocol() != MpcProtocol::kBooleanAstra) {
    auto sharing_type = to_string(parent->GetProtocol());
    throw(
        std::runtime_error((fmt::format("BooleanAstra output gate expects a BooleanAstra share, "
                                        "got a share of type {}",
                                        sharing_type))));
  }
  auto my_id = static_cast<std::int64_t>(GetCommunicationLayer().GetMyId());

  parent_ = parent->GetWires();
  output_owner_ = output_owner;
  
  size_t bitlen = parent_.size();
  output_wires_.reserve(bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    auto parent_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_[s]);
    assert(parent_wire);
    auto const& values = parent_wire->GetValues();
    auto const& lambdas1 = parent_wire->GetLambdas1();
    auto const& lambdas2 = parent_wire->GetLambdas2();
    output_wires_.emplace_back(
      GetRegister().template EmplaceWire<boolean_astra::Wire>(
        backend_, values, lambdas1, lambdas2));
  }

  if (output_owner_ == my_id || output_owner_ == kAll) {
    output_future_ = GetCommunicationLayer().GetMessageManager().RegisterReceive(
        (my_id + 1) % 3, communication::MessageType::kBooleanAstraOutputGate, gate_id_);
  }
}

void OutputGate::EvaluateSetup() {
  SetSetupReady(output_wires_);
}

void OutputGate::EvaluateOnline() {
  using namespace std::string_literals;
  using std::to_string;
  using communication::MessageType::kBooleanAstraOutputGate;
  WaitSetup();
  assert(setup_is_ready_);

  size_t bitlen = parent_.size();
  assert(bitlen == output_wires_.size());

  auto& communication_layer = GetCommunicationLayer();
  auto my_id = static_cast<std::int64_t>(communication_layer.GetMyId());
  
  // wait for parent wires to obtain a value
  for(size_t s = 0; s != bitlen; ++s) {
    parent_[s]->GetIsReadyCondition().Wait();
  }
  
  switch (my_id) {
    case 0: {
      //Send lambda1 to P2
      if (output_owner_ == 2 || output_owner_ == kAll) {
        SendLambdas1(parent_, 2, gate_id_, communication_layer, kBooleanAstraOutputGate);
      }

      if(output_owner_ == my_id || output_owner_ == kAll) {
        //Receive mx ^ lambda from P1
        const auto output_message = output_future_.get();
        const auto payload = communication::GetMessage(output_message.data())->payload();
        AssignValues(output_wires_, {payload->Data(), payload->size()});
        for(size_t s = 0; s != bitlen; ++s) {
          auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
          assert(out_wire);
          auto in_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_[s]);
          assert(in_wire);
          auto const& in_lambdas1 = in_wire->GetLambdas1();
          auto const& in_lambdas2 = in_wire->GetLambdas2();
          auto& out_values = out_wire->GetMutableValues();
          out_values ^= in_lambdas1;
          out_values ^= in_lambdas2;
        }
      }
      break;
    }
    case 1: {
      //Send lambda1 to P0
      if (output_owner_ == 0 || output_owner_ == kAll) {
        SendValues(parent_, 0, gate_id_, communication_layer, kBooleanAstraOutputGate);
      }

      if (output_owner_ == my_id || output_owner_ == kAll) {
        //Receive lambda2 from P2
        const auto message = output_future_.get();
        const auto payload = communication::GetMessage(message.data())->payload();
        AssignValues(output_wires_, {payload->Data(), payload->size()});
        for(size_t s = 0; s != bitlen; ++s) {
          auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
          assert(out_wire);
          auto in_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_[s]);
          assert(in_wire);
          auto const& in_lambdas1 = in_wire->GetLambdas1();
          auto const& in_values = in_wire->GetValues();
          auto& out_values = out_wire->GetMutableValues();
          out_values ^= in_lambdas1;
          out_values ^= in_values;
        }
      }
      break;
    }
    case 2: {
      //Send lambda2 to P1 
      if (output_owner_ == 1 || output_owner_ == kAll) {
        SendLambdas2(parent_, 1, gate_id_, communication_layer, kBooleanAstraOutputGate);
      }

      if (output_owner_ == my_id || output_owner_ == kAll) {
        //Receive lambda1 from P0
        const auto message = output_future_.get();
        const auto payload = communication::GetMessage(message.data())->payload();
        AssignValues(output_wires_, {payload->Data(), payload->size()});
        for(size_t s = 0; s != bitlen; ++s) {
          auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
          assert(out_wire);
          auto in_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_[s]);
          assert(in_wire);
          auto const& in_lambdas2 = in_wire->GetLambdas2();
          auto const& in_values = in_wire->GetValues();
          auto& out_values = out_wire->GetMutableValues();
          out_values ^= in_lambdas2;
          out_values ^= in_values;
        }
      }
      break;
    }
  }  
}

boolean_astra::SharePointer OutputGate::GetOutputAsBooleanAstraShare() {
  return std::make_shared<boolean_astra::Share>(output_wires_);
}


XorGate::XorGate(ShareWrapper const& a, ShareWrapper const& b)
: Base(a->GetBackend()) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();
  
  size_t bitlen = parent_a_.size();
  assert(parent_b_.size() == bitlen);
  
  output_wires_.reserve(bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[s]);
    auto const& a_values = a_wire->GetValues();
    auto const& a_lambdas1 = a_wire->GetLambdas1();
    auto const& a_lambdas2 = a_wire->GetLambdas2();
    output_wires_.emplace_back(
      GetRegister().template EmplaceWire<boolean_astra::Wire>(
        backend_, a_values, a_lambdas1, a_lambdas2));
  }
  assert(output_wires_.size() == bitlen);
}

void XorGate::EvaluateSetup() {
  size_t bitlen = parent_a_.size();
  for(size_t s = 0; s != bitlen; ++s) {
    auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[s]);
    assert(a_wire);
    auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[s]);
    assert(b_wire);
    auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
    assert(out_wire);
    auto const& a_lambdas1 = a_wire->GetLambdas1();
    auto const& a_lambdas2 = a_wire->GetLambdas2();
    auto const& b_lambdas1 = b_wire->GetLambdas1();
    auto const& b_lambdas2 = b_wire->GetLambdas2();
    auto& out_lambdas1 = out_wire->GetMutableLambdas1();
    auto& out_lambdas2 = out_wire->GetMutableLambdas2();
    a_wire->GetSetupReadyCondition()->Wait();
    b_wire->GetSetupReadyCondition()->Wait();
    assert(a_lambdas1.GetSize() == b_lambdas1.GetSize());
    assert(a_lambdas2.GetSize() == b_lambdas2.GetSize());
    out_lambdas1 = a_lambdas1 ^ b_lambdas1;
    out_lambdas2 = a_lambdas2 ^ b_lambdas2;
    out_wire->SetSetupIsReady();
  }
}

void XorGate::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  size_t bitlen = parent_a_.size();
  for(size_t s = 0; s != bitlen; ++s) {
    auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[s]);
    assert(a_wire);
    auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[s]);
    assert(b_wire);
    auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
    assert(out_wire);
    auto const& a_values = a_wire->GetValues();
    auto const& b_values = b_wire->GetValues();
    auto& out_values = out_wire->GetMutableValues();
    a_wire->GetIsReadyCondition().Wait();
    b_wire->GetIsReadyCondition().Wait();
    assert(a_values.GetSize() == b_values.GetSize());
    out_values = a_values ^ b_values;
  }
}

boolean_astra::SharePointer XorGate::GetOutputAsBooleanAstraShare() {
  return std::make_shared<boolean_astra::Share>(output_wires_);
}

AndGate::AndGate(ShareWrapper const& a, ShareWrapper const& b)
: Base(a->GetBackend()) {
  using communication::MessageType::kBooleanAstraSetupAndGate;
  using communication::MessageType::kBooleanAstraOnlineAndGate;
  
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();
  
  size_t bitlen = parent_a_.size();
  assert(parent_b_.size() == bitlen);
  
  output_wires_.reserve(bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[s]);
    auto const& a_values = a_wire->GetValues();
    auto const& a_lambdas1 = a_wire->GetLambdas1();
    auto const& a_lambdas2 = a_wire->GetLambdas2();
    output_wires_.emplace_back(
      GetRegister().template EmplaceWire<boolean_astra::Wire>(
        backend_, a_values, a_lambdas1, a_lambdas2));
  }
  assert(output_wires_.size() == bitlen);

  auto& communication_layer = GetCommunicationLayer();
  std::size_t my_id = communication_layer.GetMyId();
  auto& message_manager = communication_layer.GetMessageManager();
  if (my_id == 1) {
    multiply_future_online_ = message_manager.RegisterReceive(
        2, kBooleanAstraOnlineAndGate, gate_id_);
  } else if (my_id == 2) {
    multiply_future_setup_ = message_manager.RegisterReceive(
        0, kBooleanAstraSetupAndGate, gate_id_);
    multiply_future_online_ = message_manager.RegisterReceive(
        1, kBooleanAstraOnlineAndGate, gate_id_);
  }
}

void AndGate::EvaluateSetup() {
  using communication::MessageType::kBooleanAstraSetupAndGate;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  size_t bitlen = parent_a_.size();

  switch (my_id) {
    case 0: {
      auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
      auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
      
      SetLambdas1AndValuesToRandom(output_wires_, rng1, gate_id_);
      //lambda_1, gamma_ab_1 are in out_lambdas, out_values
      SetLambdas2ToRandom(output_wires_, rng2, gate_id_);
      //Now lambda is in out_lambdas
      SetSetupReady(output_wires_);

      for (size_t s = 0; s != bitlen; ++s) {
        auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
        assert(out_wire);
        auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[s]);
        assert(a_wire);
        auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[s]);
        assert(b_wire);
        a_wire->GetSetupReadyCondition()->Wait();
        b_wire->GetSetupReadyCondition()->Wait();
        auto& out_values = out_wire->GetMutableValues();
        auto const& a_lambdas1 = a_wire->GetLambdas1();
        auto const& a_lambdas2 = a_wire->GetLambdas2();
        auto const& b_lambdas1 = b_wire->GetLambdas1();
        auto const& b_lambdas2 = b_wire->GetLambdas2();
        out_values ^= (a_lambdas1 ^ a_lambdas2) & (b_lambdas1 ^ b_lambdas2);
      }
      //Now gamma_ab_2 is in out_values
      SendValues(output_wires_, 2, gate_id_, communication_layer, kBooleanAstraSetupAndGate);
      break;
    }
    case 1: {
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      SetLambdas1AndValuesToRandom(output_wires_, rng0, gate_id_);
      SetSetupReady(output_wires_);
      break;
    }
    case 2: {
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      SetLambdas2ToRandom(output_wires_, rng0, gate_id_);
      SetSetupReady(output_wires_);
      
      const auto message = multiply_future_setup_.get();
      const auto payload = communication::GetMessage(message.data())->payload();
      AssignValues(output_wires_, {payload->Data(), payload->size()});
      //Now gamma_ab_2 is in out_values
    }
  }
  
}

void AndGate::EvaluateOnline() {
  using communication::MessageType::kBooleanAstraOnlineAndGate;
  WaitSetup();
  assert(setup_is_ready_);
  
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  size_t bitlen = parent_a_.size();

  if (my_id != 0) {
    switch (my_id) {
      case 1: {
        //out_values contains gamma_ab_1
        for (auto s = 0u; s != bitlen; ++s) {
          auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
          assert(out_wire);
          auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[s]);
          assert(a_wire);
          auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[s]);
          assert(b_wire);
          a_wire->GetIsReadyCondition().Wait();
          b_wire->GetIsReadyCondition().Wait();
          auto& out_values = out_wire->GetMutableValues();
          auto const& out_lambdas1 = out_wire->GetLambdas1();
          auto const& a_values = a_wire->GetValues();
          auto const& a_lambdas1 = a_wire->GetLambdas1();
          auto const& b_values = b_wire->GetValues();
          auto const& b_lambdas1 = b_wire->GetLambdas1();
          out_values ^= (a_values & b_lambdas1) ^
                        (a_lambdas1 & b_values) ^ 
                        out_lambdas1;
        }
        SendValues(output_wires_, 2, gate_id_, communication_layer, kBooleanAstraOnlineAndGate);
        const auto message = multiply_future_online_.get();
        const auto payload = communication::GetMessage(message.data())->payload();
        XorAssignValues(output_wires_, {payload->Data(), payload->size()});
        break;
      }
      case 2: {
        //out_values contains gamma_ab_2
        for (auto s = 0u; s != bitlen; ++s) {
          auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
          assert(out_wire);
          auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[s]);
          assert(a_wire);
          auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[s]);
          assert(b_wire);
          a_wire->GetIsReadyCondition().Wait();
          b_wire->GetIsReadyCondition().Wait();
          auto& out_values = out_wire->GetMutableValues();
          auto const& out_lambdas2 = out_wire->GetLambdas2();
          auto const& a_values = a_wire->GetValues();
          auto const& a_lambdas2 = a_wire->GetLambdas2();
          auto const& b_values = b_wire->GetValues();
          auto const& b_lambdas2 = b_wire->GetLambdas2();
          out_values ^= (a_values & b_values) ^ 
                        (a_values & b_lambdas2) ^ 
                        (a_lambdas2 & b_values) ^
                        out_lambdas2;
        }
        SendValues(output_wires_, 1, gate_id_, communication_layer, kBooleanAstraOnlineAndGate);
        const auto message = multiply_future_online_.get();
        const auto payload = communication::GetMessage(message.data())->payload();
        XorAssignValues(output_wires_, {payload->Data(), payload->size()});
        break;
      }
    }
  }
}

boolean_astra::SharePointer AndGate::GetOutputAsBooleanAstraShare() {
  return std::make_shared<boolean_astra::Share>(output_wires_);
}

namespace {
  size_t GetTotalNumberOfBits(std::vector<motion::WirePointer> wires) {
    size_t result = 0;
    for(auto const& w : wires) {
      result += w->GetNumberOfSimdValues();
    }
    return result;
  }
  
  size_t GetNumberOfBytesToFitBits(size_t bits) {
    return (bits + CHAR_BIT - 1)/CHAR_BIT;
  }
} // namespace (anonymous)

MaliciousAndGate::MaliciousAndGate(ShareWrapper const& a, ShareWrapper const& b)
: Base(a->GetBackend()),
  triple_{backend_.GetAstraVerifier()->ReserveTriples64(GetTotalNumberOfBits(a->GetWires()))} {
  
  using communication::MessageType::kBooleanAstraSetupAndGate;
  using communication::MessageType::kBooleanAstraOnlineAndGate;
  
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();
  
  size_t bitlen = parent_a_.size();
  assert(parent_b_.size() == bitlen);
  assert(0 < bitlen);
  
  output_wires_.reserve(bitlen);
  for(size_t s = 0; s != bitlen; ++s) {
    auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[s]);
    auto const& a_values = a_wire->GetValues();
    auto const& a_lambdas1 = a_wire->GetLambdas1();
    auto const& a_lambdas2 = a_wire->GetLambdas2();
    output_wires_.emplace_back(
      GetRegister().template EmplaceWire<boolean_astra::Wire>(
        backend_, a_values, a_lambdas1, a_lambdas2));
  }
  assert(output_wires_.size() == bitlen);

  auto& communication_layer = GetCommunicationLayer();
  std::size_t my_id = communication_layer.GetMyId();
  auto& message_manager = communication_layer.GetMessageManager();
  if (my_id == 1) {
    multiply_future_online_ = message_manager.RegisterReceive(
        2, kBooleanAstraOnlineAndGate, gate_id_);
  } else if (my_id == 2) {
    multiply_future_setup_ = message_manager.RegisterReceive(
        0, kBooleanAstraSetupAndGate, gate_id_);
    multiply_future_online_ = message_manager.RegisterReceive(
        1, kBooleanAstraOnlineAndGate, gate_id_);
  }
}

void MaliciousAndGate::EvaluateSetup() {
  using communication::MessageType::kBooleanAstraSetupAndGate;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  size_t const bitlen = parent_a_.size();
  size_t const total_number_of_bits = GetTotalNumberOfBits(parent_a_);
  assert(parent_b_.size() == bitlen);
  assert(GetTotalNumberOfBits(parent_b_) == total_number_of_bits);
  
  //Calculate the number of bytes needed for lambdas1/lambdas2
  size_t lambdas_bytes = 0;
  for(size_t s = 0; s != bitlen; ++s) {
    size_t const number_of_simd_values = parent_a_[s]->GetNumberOfSimdValues();
    assert(number_of_simd_values == parent_b_[s]->GetNumberOfSimdValues());
    lambdas_bytes += GetNumberOfBytesToFitBits(number_of_simd_values);
  }
  
  switch(my_id) {
    case 0: {
      auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
      auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
      
      size_t const gamma1_ab_extended_bytes = total_number_of_bits * sizeof(uint64_t);
      std::vector<uint8_t> randoms1 = 
        rng1.template GetUnsigned<uint8_t>(gate_id_, lambdas_bytes + gamma1_ab_extended_bytes);
      std::vector<uint8_t> randoms2 = 
        rng2.template GetUnsigned<uint8_t>(gate_id_, lambdas_bytes);
      {  
        uint8_t* lambdas1_iterator = randoms1.data();
        uint8_t* lambdas2_iterator = randoms2.data();
        for(size_t s = 0; s != bitlen; ++s) {
          size_t const number_of_simd_values = parent_a_[s]->GetNumberOfSimdValues();
          auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
          assert(out_wire);
          auto& out_lambdas1 = out_wire->GetMutableLambdas1();
          auto& out_lambdas2 = out_wire->GetMutableLambdas2();
          out_lambdas1.Assign(BitVector<>(lambdas1_iterator, number_of_simd_values));
          lambdas1_iterator += GetNumberOfBytesToFitBits(number_of_simd_values);
          out_lambdas2.Assign(BitVector<>(lambdas2_iterator, number_of_simd_values));
          lambdas2_iterator += GetNumberOfBytesToFitBits(number_of_simd_values);
        }
      }
      SetSetupReady(output_wires_);
        
      std::vector<uint64_t> message_gamma2_ab;
      message_gamma2_ab.reserve(total_number_of_bits);
      {
        uint8_t* gamma1_ab_extended_iterator = randoms1.data() + lambdas_bytes;
        for(size_t s = 0; s != bitlen; ++s) {
          size_t const number_of_simd_values = parent_a_[s]->GetNumberOfSimdValues();
          auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[s]);
          assert(a_wire);
          auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[s]);
          assert(b_wire);
          a_wire->GetSetupReadyCondition()->Wait();
          b_wire->GetSetupReadyCondition()->Wait();
          auto const& a_lambdas1 = a_wire->GetLambdas1();
          auto const& a_lambdas2 = a_wire->GetLambdas2();
          auto const& b_lambdas1 = b_wire->GetLambdas1();
          auto const& b_lambdas2 = b_wire->GetLambdas2();
        
          for(size_t i = 0; i != number_of_simd_values; ++i) {
            uint64_t lambda_a = uint64_t(a_lambdas1.Get(i)) + uint64_t(a_lambdas2.Get(i));
            uint64_t lambda_b = uint64_t(b_lambdas1.Get(i)) + uint64_t(b_lambdas2.Get(i));
            uint64_t gamma_ab = lambda_a * lambda_b;
            triple_.AppendTriple(lambda_a, lambda_b, gamma_ab);
            uint64_t gamma1_ab;
            memcpy(&gamma1_ab, gamma1_ab_extended_iterator, sizeof(uint64_t));
            gamma1_ab_extended_iterator += sizeof(uint64_t);
            message_gamma2_ab.emplace_back(gamma_ab - gamma1_ab);
          }
        }
      }
      backend_.GetAstraVerifier()->SetReady();
      auto payload = ToByteVector<uint64_t>(message_gamma2_ab);
      auto message = communication::BuildMessage(kBooleanAstraSetupAndGate, gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
      break;
    }
    case 1: {
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      
      size_t const gamma1_ab_extended_bytes = total_number_of_bits * sizeof(uint64_t);
      std::vector<uint8_t> randoms0 = 
        rng0.template GetUnsigned<uint8_t>(gate_id_, lambdas_bytes + gamma1_ab_extended_bytes);
      {  
        uint8_t* lambdas1_iterator = randoms0.data();
        for(size_t s = 0; s != bitlen; ++s) {
          size_t const number_of_simd_values = parent_a_[s]->GetNumberOfSimdValues();
          auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
          assert(out_wire);
          auto& out1_lambdas = out_wire->GetMutableLambdas1();
          out1_lambdas.Assign(BitVector<>(lambdas1_iterator, number_of_simd_values));
          lambdas1_iterator += GetNumberOfBytesToFitBits(number_of_simd_values);
        }
      }
      SetSetupReady(output_wires_);
      
      {
        uint8_t* gamma1_ab_extended_iterator = randoms0.data() + lambdas_bytes;
        for(size_t s = 0; s != bitlen; ++s) {
          size_t const number_of_simd_values = parent_a_[s]->GetNumberOfSimdValues();
          auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
          assert(out_wire);
          auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[s]);
          assert(a_wire);
          auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[s]);
          assert(b_wire);
          a_wire->GetSetupReadyCondition()->Wait();
          b_wire->GetSetupReadyCondition()->Wait();
          auto& out_values = out_wire->GetMutableValues();
          auto const& a_lambdas1 = a_wire->GetLambdas1();
          auto const& b_lambdas1 = b_wire->GetLambdas1();
        
          for(size_t i = 0; i != number_of_simd_values; ++i) {
            uint64_t lambda1_a = a_lambdas1.Get(i);
            uint64_t lambda1_b = b_lambdas1.Get(i);
            uint64_t gamma1_ab;
            memcpy(&gamma1_ab, gamma1_ab_extended_iterator, sizeof(uint64_t));
            triple_.AppendTriple(lambda1_a, lambda1_b, gamma1_ab);
            out_values.Set(bool(gamma1_ab & 0x1), i);
            gamma1_ab_extended_iterator += sizeof(uint64_t);
          }
        }
        //gamma1_ab is in out_values
        backend_.GetAstraVerifier()->SetReady();
        break;
      }
    }
    case 2: {
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      std::vector<uint8_t> randoms0 = 
        rng0.template GetUnsigned<uint8_t>(gate_id_, lambdas_bytes);
      {  
        uint8_t* lambdas2_iterator = randoms0.data();
        for(size_t s = 0; s != bitlen; ++s) {
          size_t const number_of_simd_values = parent_a_[s]->GetNumberOfSimdValues();
          auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
          assert(out_wire);
          auto& out_lambdas2 = out_wire->GetMutableLambdas2();
          out_lambdas2.Assign(BitVector<>(lambdas2_iterator, number_of_simd_values));
          lambdas2_iterator += GetNumberOfBytesToFitBits(number_of_simd_values);
        }
      }
      SetSetupReady(output_wires_);
      
      {
        const auto message = multiply_future_setup_.get();
        const auto payload = communication::GetMessage(message.data())->payload();
        std::vector<uint64_t> message_gamma_ab2 = 
          FromByteVector<uint64_t>({payload->Data(), payload->size()});
        auto message_gamma_ab2_iterator = message_gamma_ab2.begin();
        for(size_t s = 0; s != bitlen; ++s) {
          size_t const number_of_simd_values = parent_a_[s]->GetNumberOfSimdValues();
          auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
          assert(out_wire);
          auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[s]);
          assert(a_wire);
          auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[s]);
          assert(b_wire);
          a_wire->GetSetupReadyCondition()->Wait();
          b_wire->GetSetupReadyCondition()->Wait();
          auto& out_values = out_wire->GetMutableValues();
          auto const& a_lambdas2 = a_wire->GetLambdas2();
          auto const& b_lambdas2 = b_wire->GetLambdas2();
          
          for(size_t i = 0; i != number_of_simd_values; ++i, ++message_gamma_ab2_iterator) {
            assert(message_gamma_ab2_iterator != message_gamma_ab2.end());
            uint64_t lambda2_a = a_lambdas2.Get(i);
            uint64_t lambda2_b = b_lambdas2.Get(i);
            uint64_t gamma2_ab = *message_gamma_ab2_iterator;
            triple_.AppendTriple(lambda2_a, lambda2_b, gamma2_ab);
            out_values.Set(bool(gamma2_ab & 0x1), i);
          }
        }
        assert(message_gamma_ab2_iterator == message_gamma_ab2.end());
      }
      //gamma2_ab is in out_values
      backend_.GetAstraVerifier()->SetReady();
      break;
    }
  }
}

void MaliciousAndGate::EvaluateOnline() {
  using communication::MessageType::kBooleanAstraOnlineAndGate;
  WaitSetup();
  assert(setup_is_ready_);
  
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  size_t bitlen = parent_a_.size();

  if (my_id != 0) {
    switch (my_id) {
      case 1: {
        //out_values contains gamma_ab_1
        for (auto s = 0u; s != bitlen; ++s) {
          auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
          assert(out_wire);
          auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[s]);
          assert(a_wire);
          auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[s]);
          assert(b_wire);
          auto& out_values = out_wire->GetMutableValues();
          auto const& out_lambdas1 = out_wire->GetLambdas1();
          auto const& a_values = a_wire->GetValues();
          auto const& a_lambdas1 = a_wire->GetLambdas1();
          auto const& b_values = b_wire->GetValues();
          auto const& b_lambdas1 = b_wire->GetLambdas1();
          a_wire->GetIsReadyCondition().Wait();
          b_wire->GetIsReadyCondition().Wait();
          out_values ^= (a_values & b_lambdas1) ^
                        (a_lambdas1 & b_values) ^ 
                        out_lambdas1;
        }
        SendValues(output_wires_, 2, gate_id_, communication_layer, kBooleanAstraOnlineAndGate);
        const auto message = multiply_future_online_.get();
        const auto payload = communication::GetMessage(message.data())->payload();
        XorAssignValues(output_wires_, {payload->Data(), payload->size()});
        break;
      }
      case 2: {
        //out_values contains gamma_ab_2
        for (auto s = 0u; s != bitlen; ++s) {
          auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[s]);
          assert(out_wire);
          auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[s]);
          assert(a_wire);
          auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[s]);
          assert(b_wire);
          auto& out_values = out_wire->GetMutableValues();
          auto const& out_lambdas2 = out_wire->GetLambdas2();
          auto const& a_values = a_wire->GetValues();
          auto const& a_lambdas2 = a_wire->GetLambdas2();
          auto const& b_values = b_wire->GetValues();
          auto const& b_lambdas2 = b_wire->GetLambdas2();
          a_wire->GetIsReadyCondition().Wait();
          b_wire->GetIsReadyCondition().Wait();
          out_values ^= (a_values & b_values) ^ 
                        (a_values & b_lambdas2) ^ 
                        (a_lambdas2 & b_values) ^
                        out_lambdas2;
        }
        SendValues(output_wires_, 1, gate_id_, communication_layer, kBooleanAstraOnlineAndGate);
        const auto message = multiply_future_online_.get();
        const auto payload = communication::GetMessage(message.data())->payload();
        XorAssignValues(output_wires_, {payload->Data(), payload->size()});
        break;
      }
    }
  }
}

boolean_astra::SharePointer MaliciousAndGate::GetOutputAsBooleanAstraShare() {
  return std::make_shared<boolean_astra::Share>(output_wires_);
}

}  // namespace encrypto::motion::proto::boolean_astra
