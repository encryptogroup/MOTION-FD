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

#include <mutex>
#include <type_traits>

#include "auxiliator_gate.h"
#include "auxiliator_share.h"
#include "auxiliator_wire.h"
#include "protocols/boolean_auxiliator/boolean_auxiliator_wire.h"
#include "protocols/boolean_auxiliator/boolean_auxiliator_share.h"
#include "protocols/share_wrapper.h"
#include "communication/message_manager.h"
#include "primitives/sharing_randomness_generator.h"
#include "utility/helpers.h"

#include <iostream>
#include <string>
#include <mutex>
#include <boost/numeric/ublas/io.hpp>

using namespace std::string_literals;
using std::to_string;

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

namespace encrypto::motion::proto::auxiliator {
using std::to_string;

template <typename T>
InputGate<T>::InputGate(std::vector<T> input, std::size_t input_owner, Backend& backend)
    : Base(backend) {
  input_owner_id_ = input_owner;

  auto my_id = static_cast<std::int64_t>(GetCommunicationLayer().GetMyId());

  std::shared_ptr<auxiliator::Wire<T>> w;
  std::vector<typename auxiliator::Wire<T>::value_type> d;
  d.reserve(input.size());
  for (auto&& e : input) {
    d.emplace_back(my_id == static_cast<std::int64_t>(input_owner) ? std::move(e) : 0, 0, 0);
  }
  w = GetRegister().template EmplaceWire<auxiliator::Wire<T>>(backend_, std::move(d));

  output_wires_ = {std::move(w)};

  if (my_id != input_owner_id_ && my_id != 0) {
    input_future_ = GetCommunicationLayer().GetMessageManager().RegisterReceive(
        input_owner_id_, communication::MessageType::kAuxiliatorInputGate, gate_id_);
  }

  if constexpr (kDebug) {
    auto gate_info = fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_,
                                 input_owner_id_);
    GetLogger().LogDebug(
        fmt::format("Allocate an auxiliator::InputGate with following properties: {}", gate_info));
  }
}

template <typename T>
void InputGate<T>::EvaluateSetup() {
  auto my_id = GetCommunicationLayer().GetMyId();
  GetBaseProvider().WaitSetup();

  auto out_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto& values = out_wire->GetMutableValues();

  switch (input_owner_id_) {
    case 0:
      switch (my_id) {
        case 0: {
          auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
          auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
          std::vector<T> randoms1 = rng1.template GetUnsigned<T>(gate_id_, values.size());
          std::vector<T> randoms2 = rng2.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms1.size() == values.size());
          assert(randoms2.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms1[i];
            v.lambda2 = randoms2[i];
          }
          break;
        }
        case 1: {
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms0.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms0[i];
          }
          break;
        }
        case 2: {
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms0.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda2 = randoms0[i];
          }
          break;
        }
      }
      break;
    case 1:
      switch (my_id) {
        case 0: {
          auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          std::vector<T> randoms1 = rng1.template GetUnsigned<T>(gate_id_, values.size());
          std::vector<T> randoms_global =
              rng_global.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms1.size() == values.size());
          assert(randoms_global.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms1[i];
            v.lambda2 = randoms_global[i];
          }
          break;
        }
        case 1: {
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, values.size());
          std::vector<T> randoms_global =
              rng_global.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms0.size() == values.size());
          assert(randoms_global.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms0[i];
            v.lambda2 = randoms_global[i];
          }
          break;
        }
        case 2: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          std::vector<T> randoms_global =
              rng_global.template GetUnsigned<T>(gate_id_, values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda2 = randoms_global[i];
          }
          break;
        }
      }
      break;
    case 2:
      switch (my_id) {
        case 0: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
          std::vector<T> randoms_global =
              rng_global.template GetUnsigned<T>(gate_id_, values.size());
          std::vector<T> randoms2 = rng2.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms_global.size() == values.size());
          assert(randoms2.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms_global[i];
            v.lambda2 = randoms2[i];
          }
          break;
        }
        case 1: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          std::vector<T> randoms_global =
              rng_global.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms_global.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms_global[i];
          }
          break;
        }
        case 2: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          std::vector<T> randoms_global =
              rng_global.template GetUnsigned<T>(gate_id_, values.size());
          std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, values.size());
          assert(randoms_global.size() == values.size());
          assert(randoms0.size() == values.size());

          for (auto i = 0u; i != values.size(); ++i) {
            auto& v = values[i];
            v.lambda1 = randoms_global[i];
            v.lambda2 = randoms0[i];
          }
          break;
        }
      }
      break;
  }
  out_wire->SetSetupIsReady();
}

template <typename T>
void InputGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);

  auto out_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto& values = out_wire->GetMutableValues();

  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();

  if (static_cast<std::size_t>(input_owner_id_) == my_id) {
    std::vector<T> buffer(values.size());
    for (auto i = 0u; i != values.size(); ++i) {
      auto& v = values[i];
      T lambda_x = v.lambda1 + v.lambda2;
      v.value -= lambda_x;
      buffer[i] = v.value;
    }

    auto payload = ToByteVector<T>(buffer);
    auto message{communication::BuildMessage(communication::MessageType::kAuxiliatorInputGate, gate_id_,
                                             payload)};
    if (my_id == 0) {
      communication_layer.BroadcastMessage(message.Release());
    } else if (my_id == 1) {
      communication_layer.SendMessage(2, message.Release());
    } else if (my_id == 2) {
      communication_layer.SendMessage(1, message.Release());
    }

  } else if (my_id != 0) {
    auto input_message{input_future_.get()};
    auto payload{communication::GetMessage(input_message.data())->payload()};
    auto buffer = FromByteVector<T>({payload->Data(), payload->size()});
    assert(buffer.size() == values.size());
    for (auto i = 0u; i != buffer.size(); ++i) {
      values[i].value = std::move(buffer[i]);
    }
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated auxiliator::InputGate with id#{}", gate_id_));
  }
}

template <typename T>
auxiliator::SharePointer<T> InputGate<T>::GetOutputAsAuxiliatorShare() {
  auto wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  assert(wire);
  return std::make_shared<auxiliator::Share<T>>(wire);
}

template class InputGate<std::uint8_t>;
template class InputGate<std::uint16_t>;
template class InputGate<std::uint32_t>;
template class InputGate<std::uint64_t>;

template <typename T>
OutputGate<T>::OutputGate(const auxiliator::WirePointer<T>& parent, std::size_t output_owner)
    : Base(parent->GetBackend()) {
  assert(parent);

  if (parent->GetProtocol() != MpcProtocol::kAuxiliator) {
    auto sharing_type = to_string(parent->GetProtocol());
    throw(
        std::runtime_error((fmt::format("Auxiliator output gate expects an auxiliator share, "
                                        "got a share of type {}",
                                        sharing_type))));
  }
  auto my_id{static_cast<std::int64_t>(GetCommunicationLayer().GetMyId())};

  parent_ = {parent};
  output_owner_ = output_owner;

  std::vector<typename auxiliator::Wire<T>::value_type> v(parent->GetNumberOfSimdValues());
  auto w = GetRegister().template EmplaceWire<auxiliator::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};

  if (output_owner_ == my_id || output_owner_ == kAll) {
    output_future_ = GetCommunicationLayer().GetMessageManager().RegisterReceive(
        (my_id + 1) % 3, communication::MessageType::kAuxiliatorOutputGate, gate_id_);
  }
}

template <typename T>
OutputGate<T>::OutputGate(const auxiliator::SharePointer<T>& parent, std::size_t output_owner)
    : OutputGate((assert(parent), parent->GetAuxiliatorWire()), output_owner) {}

template <typename T>
OutputGate<T>::OutputGate(const motion::SharePointer& parent, std::size_t output_owner)
    : OutputGate(std::dynamic_pointer_cast<auxiliator::Share<T>>(parent), output_owner) {}

template <typename T>
void OutputGate<T>::EvaluateSetup() {
}

template <typename T>
void OutputGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  parent_[0]->GetIsReadyCondition().Wait();

  auto out_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  
  assert(out_wire);
  auto in_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(parent_[0]);
  assert(in_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& in_values = in_wire->GetValues();
  assert(in_values.size() == out_values.size());

  auto& communication_layer = GetCommunicationLayer();
  auto my_id = static_cast<std::int64_t>(communication_layer.GetMyId());

  switch (my_id) {
    case 0: {
      std::vector<T> message_lambda1s(in_values.size());
      for (auto i = 0u; i != message_lambda1s.size(); ++i) {
        message_lambda1s[i] = in_values[i].lambda1;
      }

      // send output message
      if (output_owner_ == 2 || output_owner_ == kAll) {
        auto payload = ToByteVector<T>(message_lambda1s);

        auto message{communication::BuildMessage(communication::MessageType::kAuxiliatorOutputGate,
                                                 gate_id_, payload)};
        communication_layer.SendMessage(2, message.Release());
      }

      const auto output_message{output_future_.get()};
      const auto payload{communication::GetMessage(output_message.data())->payload()};
      auto received_values = FromByteVector<T>({payload->Data(), payload->size()});
      assert(received_values.size() == in_values.size());
      for (auto i = 0u; i != received_values.size(); ++i) {
        auto& in = in_values[i];
        out_values[i].value = received_values[i] + in.lambda1 + in.lambda2;
      }
      break;
    }
    case 1: {
      std::vector<T> message_values(in_values.size());
      for (auto i = 0u; i != message_values.size(); ++i) {
        message_values[i] = in_values[i].value;
      }

      if (output_owner_ == 0 || output_owner_ == kAll) {
        auto payload = ToByteVector<T>(message_values);
        auto message{communication::BuildMessage(communication::MessageType::kAuxiliatorOutputGate,
                                                 gate_id_, payload)};
        communication_layer.SendMessage(0, message.Release());
      }

      if (output_owner_ == my_id || output_owner_ == kAll) {
        const auto message{output_future_.get()};
        const auto payload{communication::GetMessage(message.data())->payload()};
        auto received_lambda2s = FromByteVector<T>({payload->Data(), payload->size()});
        assert(received_lambda2s.size() == in_values.size());
        for (auto i = 0u; i != received_lambda2s.size(); ++i) {
          auto& in = in_values[i];
          out_values[i].value = in.value + in.lambda1 + received_lambda2s[i];
        }
      }
      break;
    }
    case 2: {
      std::vector<T> message_lambda2s(in_values.size());
      for (auto i = 0u; i != message_lambda2s.size(); ++i) {
        message_lambda2s[i] = in_values[i].lambda2;
      }

      if (output_owner_ == 1 || output_owner_ == kAll) {
        auto payload = ToByteVector<T>(message_lambda2s);
        auto message{communication::BuildMessage(communication::MessageType::kAuxiliatorOutputGate,
                                                 gate_id_, payload)};
        communication_layer.SendMessage(1, message.Release());
      }

      if (output_owner_ == my_id || output_owner_ == kAll) {
        const auto message{output_future_.get()};
        const auto payload{communication::GetMessage(message.data())->payload()};
        auto received_lambda1s = FromByteVector<T>({payload->Data(), payload->size()});
        assert(received_lambda1s.size() == in_values.size());
        for (auto i = 0u; i != received_lambda1s.size(); ++i) {
          auto& in = in_values[i];
          out_values[i].value = in.value + received_lambda1s[i] + in.lambda2;
        }
      }
      break;
    }
    default: {
      assert(false);
    }
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated auxiliator::OutputGate with id#{}", gate_id_));
  }
}

template <typename T>
auxiliator::SharePointer<T> OutputGate<T>::GetOutputAsAuxiliatorShare() {
  auto wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  assert(wire);
  return std::make_shared<auxiliator::Share<T>>(wire);
}

template class OutputGate<std::uint8_t>;
template class OutputGate<std::uint16_t>;
template class OutputGate<std::uint32_t>;
template class OutputGate<std::uint64_t>;

template <typename T>
AdditionGate<T>::AdditionGate(const auxiliator::WirePointer<T>& a, const auxiliator::WirePointer<T>& b)
    : TwoGate(a->GetBackend()) {
  assert(a->GetNumberOfSimdValues() == b->GetNumberOfSimdValues());
  parent_a_ = {std::move(a)};
  parent_b_ = {std::move(b)};

  std::vector<typename auxiliator::Wire<T>::value_type> v(parent_a_[0]->GetNumberOfSimdValues());
  auto w = GetRegister().template EmplaceWire<auxiliator::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_[0]->GetWireId(), parent_b_[0]->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created an auxiliator::AdditionGate with following properties: {}", gate_info));
  }
}

template <typename T>
void AdditionGate<T>::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(parent_b_[0]);
  assert(b_wire);
  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();

  assert(out_values.size() == a_values.size());
  assert(a_values.size() == b_values.size());

  auto my_id = GetCommunicationLayer().GetMyId();

  switch (my_id) {
    case 0: {
      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        auto& a = a_values[i];
        auto& b = b_values[i];

        out.lambda1 = a.lambda1 + b.lambda1;
        out.lambda2 = a.lambda2 + b.lambda2;
      }
      break;
    }
    case 1: {
      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        auto& a = a_values[i];
        auto& b = b_values[i];

        out.lambda1 = a.lambda1 + b.lambda1;
      }
      break;
    }
    case 2: {
      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        auto& a = a_values[i];
        auto& b = b_values[i];

        out.lambda2 = a.lambda2 + b.lambda2;
      }
      break;
    }
  }
  out_wire->SetSetupIsReady();
}

template <typename T>
void AdditionGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();

  auto out_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(parent_b_[0]);
  assert(b_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();

  auto my_id = GetCommunicationLayer().GetMyId();

  if (my_id != 0) {
    for (auto i = 0u; i != out_values.size(); ++i) {
      auto& out = out_values[i];
      auto& a = a_values[i];
      auto& b = b_values[i];

      out.value = a.value + b.value;
    }
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated auxiliator::AdditionGate with id#{}", gate_id_));
  }
}

template <typename T>
auxiliator::SharePointer<T> AdditionGate<T>::GetOutputAsAuxiliatorShare() {
  auto wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  assert(wire);
  return std::make_shared<auxiliator::Share<T>>(wire);
}

template class AdditionGate<std::uint8_t>;
template class AdditionGate<std::uint16_t>;
template class AdditionGate<std::uint32_t>;
template class AdditionGate<std::uint64_t>;

template <typename T>
SubtractionGate<T>::SubtractionGate(const auxiliator::WirePointer<T>& a, const auxiliator::WirePointer<T>& b)
    : TwoGate(a->GetBackend()) {
  assert(a->GetNumberOfSimdValues() == b->GetNumberOfSimdValues());
  parent_a_ = {std::move(a)};
  parent_b_ = {std::move(b)};

  std::vector<typename auxiliator::Wire<T>::value_type> v(parent_a_[0]->GetNumberOfSimdValues());
  auto w = GetRegister().template EmplaceWire<auxiliator::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_[0]->GetWireId(), parent_b_[0]->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created an auxiliator::Subtraction with following properties: {}", gate_info));
  }
}

template <typename T>
void SubtractionGate<T>::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(parent_b_[0]);
  assert(b_wire);
  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();

  auto my_id = GetCommunicationLayer().GetMyId();

  switch (my_id) {
    case 0: {
      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        auto& a = a_values[i];
        auto& b = b_values[i];

        out.lambda1 = a.lambda1 - b.lambda1;
        out.lambda2 = a.lambda2 - b.lambda2;
      }
      break;
    }
    case 1: {
      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        auto& a = a_values[i];
        auto& b = b_values[i];

        out.lambda1 = a.lambda1 - b.lambda1;
      }
      break;
    }
    case 2: {
      for (auto i = 0u; i != out_values.size(); ++i) {
        auto& out = out_values[i];
        auto& a = a_values[i];
        auto& b = b_values[i];

        out.lambda2 = a.lambda2 - b.lambda2;
      }
      break;
    }
  }

  out_wire->SetSetupIsReady();
}

template <typename T>
void SubtractionGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();

  auto out_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(parent_b_[0]);
  assert(b_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();

  auto my_id = GetCommunicationLayer().GetMyId();

  if (my_id != 0) {
    for (auto i = 0u; i != out_values.size(); ++i) {
      auto& out = out_values[i];
      auto& a = a_values[i];
      auto& b = b_values[i];

      out.value = a.value - b.value;
    }
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated auxiliator::SubtractionGate with id#{}", gate_id_));
  }
}

template <typename T>
auxiliator::SharePointer<T> SubtractionGate<T>::GetOutputAsAuxiliatorShare() {
  auto wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  assert(wire);
  return std::make_shared<auxiliator::Share<T>>(wire);
}

template class SubtractionGate<std::uint8_t>;
template class SubtractionGate<std::uint16_t>;
template class SubtractionGate<std::uint32_t>;
template class SubtractionGate<std::uint64_t>;

template<typename T>
MatrixConversionGate<T>::MatrixConversionGate(boost::numeric::ublas::matrix<ShareWrapper> const& wires) 
: Base(wires(0, 0)->GetBackend()), wires_(wires) {
  
  size_t n = wires.size1();
  size_t m = wires.size2();
  size_t number_of_simd_values = wires(0, 0)->GetNumberOfSimdValues();

  auto w = GetRegister().template EmplaceWire<auxiliator::MatrixWire<T>>(backend_, n, m, number_of_simd_values);
  output_wires_ = {std::move(w)};
  
}

template<typename T>
void MatrixConversionGate<T>::EvaluateSetup() {
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto& out_lambda_matrices = matrix_out_wire->GetMutableLambdaMatrices();
  auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
  
  for(size_t i = 0; i != wires_.size1(); ++i) {
    for(size_t j = 0; j != wires_.size2(); ++j) {
      auto s = std::dynamic_pointer_cast<auxiliator::Share<T>>(wires_(i, j).Get());
      assert(s);
      auto w = s->GetAuxiliatorWire();
      w->GetSetupReadyCondition()->Wait();
      auto const& values = w->GetValues();
      for(size_t s = 0; s != values.size(); ++s) {
        switch(my_id) {
          case 0: {
            out_value_matrices[s](i, j) = values[s].lambda1;
            out_lambda_matrices[s](i,j) = values[s].lambda2;
            break;
          }
          case 1: {
            out_lambda_matrices[s](i, j) = values[s].lambda1;
            break;
          }
          case 2: {
            out_lambda_matrices[s](i, j) = values[s].lambda2;
            break;
          }
        }
      }
    }
  }
  matrix_out_wire->SetSetupIsReady();
}

template<typename T>
void MatrixConversionGate<T>::EvaluateOnline() {
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  if(0 != my_id) {
    auto matrix_out_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
    assert(matrix_out_wire);
    auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
    
    for(size_t i = 0; i != wires_.size1(); ++i) {
      for(size_t j = 0; j != wires_.size2(); ++j) {
        auto s = std::dynamic_pointer_cast<auxiliator::Share<T>>(wires_(i, j).Get());
        assert(s);
        auto w = s->GetAuxiliatorWire();
        w->GetIsReadyCondition().Wait();
        auto const& values = w->GetValues();
        for(size_t s = 0; s != values.size(); ++s) {
          out_value_matrices[s](i, j) = values[s].value;
        }
      }
    }
  }
}

template class MatrixConversionGate<std::uint8_t>;
template class MatrixConversionGate<std::uint16_t>;
template class MatrixConversionGate<std::uint32_t>;
template class MatrixConversionGate<std::uint64_t>;

template<typename T>
MatrixReconversionGate<T>::MatrixReconversionGate(ShareWrapper const& share_wrapper) 
: Base(share_wrapper->GetBackend()) {
  
  auto wires = share_wrapper->GetWires();
  auto matrix_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(wires[0]);
  assert(matrix_wire);
  
  auto const& lambda_matrices = matrix_wire->GetLambdaMatrices(); 
    
  size_t number_of_simd_values = lambda_matrices.size();
  size_t m = lambda_matrices[0].size1();
  size_t n = lambda_matrices[0].size2();
  share_matrix_.resize(m, n);
  
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      std::vector<typename auxiliator::Wire<T>::value_type> v(number_of_simd_values);
      auto w = GetRegister().template EmplaceWire<auxiliator::Wire<T>>(backend_, std::move(v));
      share_matrix_(i, j) = ShareWrapper(std::make_shared<auxiliator::Share<T>>(std::move(w)));
    }
  }

  matrix_input_wire_ = std::move(matrix_wire);
  
}

template<typename T>
void MatrixReconversionGate<T>::EvaluateSetup() {
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto& in_lambda_matrices = matrix_input_wire_->GetMutableLambdaMatrices();
  auto& in_value_matrices = matrix_input_wire_->GetMutableValueMatrices();
  size_t number_of_simd_values = in_lambda_matrices.size();
  
  matrix_input_wire_->GetSetupReadyCondition()->Wait();
  
  size_t m = in_lambda_matrices[0].size1();
  size_t n = in_lambda_matrices[0].size2();
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      auto w = std::dynamic_pointer_cast<auxiliator::Wire<T>>(share_matrix_(i, j)->GetWires()[0]);
      auto& values = w->GetMutableValues();
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        switch(my_id) {
          case 0: {
            values[s].lambda1 = in_value_matrices[s](i, j);
            values[s].lambda2 = in_lambda_matrices[s](i, j);
            break;    
          }
          case 1: {
            values[s].lambda1 = in_lambda_matrices[s](i, j);
            break;
          }
          case 2: {
            values[s].lambda2 = in_lambda_matrices[s](i, j);
            break;
          }
        }
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
  auto my_id = GetCommunicationLayer().GetMyId();
  matrix_input_wire_->GetIsReadyCondition().Wait();
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      auto w = std::dynamic_pointer_cast<auxiliator::Wire<T>>(share_matrix_(i, j)->GetWires()[0]);
      if(my_id != 0) {
        auto& values = w->GetMutableValues();
        for(size_t s = 0; s != number_of_simd_values; ++s) {
          values[s].value = in_value_matrices[s](i, j);
        }
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
MatrixSimdReconversionGate<T>::MatrixSimdReconversionGate(ShareWrapper const& share_wrapper) 
: Base(share_wrapper->GetBackend()) {
  
  auto wires = share_wrapper->GetWires();
  auto matrix_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(wires[0]);
  assert(matrix_wire);
  
  auto const& lambda_matrices = matrix_wire->GetLambdaMatrices(); 
    
  size_t const number_of_matrix_simd_values = lambda_matrices.size();
  size_t const m = lambda_matrices[0].size1();
  size_t const n = lambda_matrices[0].size2();
  size_t const number_of_simd_values = number_of_matrix_simd_values * m * n;
  
  std::vector<typename auxiliator::Wire<T>::value_type> v(number_of_simd_values);
  auto w = GetRegister().template EmplaceWire<auxiliator::Wire<T>>(backend_, std::move(v));
  simd_share_ = ShareWrapper(std::make_shared<auxiliator::Share<T>>(std::move(w)));

  matrix_input_wire_ = std::move(matrix_wire);
}

template<typename T>
void MatrixSimdReconversionGate<T>::EvaluateSetup() {
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto& in_lambda_matrices = matrix_input_wire_->GetMutableLambdaMatrices();
  auto& in_value_matrices = matrix_input_wire_->GetMutableValueMatrices();
  
  matrix_input_wire_->GetSetupReadyCondition()->Wait();
  
  size_t const number_of_matrix_simd_values = in_lambda_matrices.size();
  size_t const m = in_lambda_matrices[0].size1();
  size_t const n = in_lambda_matrices[0].size2();
  
  auto w = std::dynamic_pointer_cast<auxiliator::Wire<T>>(simd_share_->GetWires()[0]);
  auto& values = w->GetMutableValues();
  {
    size_t offset = 0;
    for(size_t s = 0; s != number_of_matrix_simd_values; ++s) {
      for(size_t i = 0; i != m; ++i) {
        for(size_t j = 0; j != n; ++j) {
          switch(my_id) {
            case 0: {
              values[offset].lambda1 = in_value_matrices[s](i, j);
              values[offset].lambda2 = in_lambda_matrices[s](i, j);
              break;    
            }
            case 1: {
              values[offset].lambda1 = in_lambda_matrices[s](i, j);
              break;
            }
            case 2: {
              values[offset].lambda2 = in_lambda_matrices[s](i, j);
              break;
            }
          }
          ++offset;
        }
      }
    }
    assert(offset == number_of_matrix_simd_values * m * n);
  }
  w->SetSetupIsReady();
}

template<typename T>
void MatrixSimdReconversionGate<T>::EvaluateOnline() {
  auto& in_value_matrices = matrix_input_wire_->GetMutableValueMatrices();
  auto my_id = GetCommunicationLayer().GetMyId();
  matrix_input_wire_->GetIsReadyCondition().Wait();
  
  size_t const number_of_matrix_simd_values = in_value_matrices.size();
  size_t const m = in_value_matrices[0].size1();
  size_t const n = in_value_matrices[0].size2();
  auto w = std::dynamic_pointer_cast<auxiliator::Wire<T>>(simd_share_->GetWires()[0]);
  auto& values = w->GetMutableValues();
  {
    size_t offset = 0;
    for(size_t s = 0; s != number_of_matrix_simd_values; ++s) {
      for(size_t i = 0; i != m; ++i) {
        for(size_t j = 0; j != n; ++j) {
          if(my_id != 0) {
            values[offset].value = in_value_matrices[s](i, j);
          }
          ++offset;
        }
      }
    }
    ++offset;
  }
  w->SetOnlineFinished();
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
void SetToRandom(
  std::vector<boost::numeric::ublas::matrix<T>>& matrices, 
  auto& rng, size_t gate_id) {
  
  size_t number_of_simd_values = matrices.size();
  size_t m = matrices[0].size1();
  size_t n = matrices[0].size2();
  auto data = rng.template GetUnsigned<T>(gate_id, number_of_simd_values * m * n);
  auto data_it = data.begin();
  for(size_t s = 0; s != number_of_simd_values; ++s) {
    for(size_t i = 0; i != m; ++i){
      for(size_t j = 0; j != n; ++j, ++data_it) {
        assert(data_it != data.end());
        matrices[s](i, j) = *data_it;
      }
    }
  }
  assert(data_it == data.end());
}

template<typename T>
void SetToRandom(
  std::vector<boost::numeric::ublas::matrix<T>>& matrices_1,
  std::vector<boost::numeric::ublas::matrix<T>>& matrices_2, 
  auto& rng, size_t gate_id) {
  
  size_t number_of_simd_values_1 = matrices_1.size();
  size_t m_1 = matrices_1[0].size1();
  size_t n_1 = matrices_1[0].size2();
  size_t number_items_1 = number_of_simd_values_1 * m_1 * n_1;
  
  size_t number_of_simd_values_2 = matrices_2.size();
  size_t m_2 = matrices_2[0].size1();
  size_t n_2 = matrices_2[0].size2();
  size_t number_items_2 = number_of_simd_values_2 * m_2 * n_2;
  
  auto data = rng.template GetUnsigned<T>(gate_id, number_items_1 + number_items_2);
  auto data_it = data.begin();
  for(size_t s = 0; s != number_of_simd_values_1; ++s) {
    for(size_t i = 0; i != m_1; ++i){
      for(size_t j = 0; j != n_1; ++j, ++data_it) {
        assert(data_it != data.end());
        matrices_1[s](i, j) = *data_it;
      }
    }
  }
  for(size_t s = 0; s != number_of_simd_values_2; ++s) {
    for(size_t i = 0; i != m_2; ++i){
      for(size_t j = 0; j != n_2; ++j, ++data_it) {
        assert(data_it != data.end());
        matrices_2[s](i, j) = *data_it;
      }
    }
  }
  assert(data_it == data.end());
}

template<typename T, typename U>
void SetToRandom(
  std::vector<boost::numeric::ublas::matrix<T>>& matrices_1,
  std::vector<boost::numeric::ublas::matrix<U>>& matrices_2, 
  auto& rng, size_t gate_id) {
  using SmallerType = std::conditional_t<(sizeof(T) < sizeof(U)), T, U>;
  using BiggerType = std::conditional_t<(sizeof(T) > sizeof(U)), T, U>;
  
  size_t number_of_simd_values_1 = matrices_1.size();
  size_t m_1 = matrices_1[0].size1();
  size_t n_1 = matrices_1[0].size2();
  size_t number_items_1 = number_of_simd_values_1 * m_1 * n_1;
  
  size_t number_of_simd_values_2 = matrices_2.size();
  size_t m_2 = matrices_2[0].size1();
  size_t n_2 = matrices_2[0].size2();
  size_t number_items_2 = number_of_simd_values_2 * m_2 * n_2;
  
  auto data = rng.template GetUnsigned<SmallerType>(
    gate_id, number_items_1 + (sizeof(BiggerType)/sizeof(SmallerType)) * number_items_2);
  auto data_it = data.begin();
  for(size_t s = 0; s != number_of_simd_values_1; ++s) {
    for(size_t i = 0; i != m_1; ++i){
      for(size_t j = 0; j != n_1; ++j, ++data_it) {
        assert(data_it != data.end());
        matrices_1[s](i, j) = *data_it;
      }
    }
  }
  auto data_ptr = reinterpret_cast<BiggerType*>(data.data() + number_items_1);
  for(size_t s = 0; s != number_of_simd_values_2; ++s) {
    for(size_t i = 0; i != m_2; ++i){
      for(size_t j = 0; j != n_2; ++j, ++data_ptr) {
        matrices_2[s](i, j) = *data_ptr;
      }
    }
  }
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
BitAGate<T>::BitAGate(boolean_auxiliator::BitMatrixWirePointer bit_matrix_wire)
: OneGate(bit_matrix_wire->GetBackend()),
  triple_(backend_.GetAuxiliatorVerifier()->ReserveTriples128(bit_matrix_wire->GetNumberOfSimdValues()))  {
  
  parent_ = {bit_matrix_wire};
  
  size_t u = bit_matrix_wire->GetNumberOfRows();
  size_t v = bit_matrix_wire->GetNumberOfColumns();
  size_t number_of_simd_values = bit_matrix_wire->GetMatrixSimdValues();

  auto w = GetRegister().template EmplaceWire<auxiliator::MatrixWire<T>>(backend_, u, v, number_of_simd_values);
  output_wires_ = {std::move(w)};

  std::size_t my_id = GetCommunicationLayer().GetMyId();
  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  //P0 never receives anything
  if (my_id == 1) {
    bit_a_future_online_ = message_manager.RegisterReceive(
        2, communication::MessageType::kAuxiliatorOnlineBitAGate, gate_id_);
  } else if (my_id == 2) {
    bit_a_future_setup_ = message_manager.RegisterReceive(
        0, communication::MessageType::kAuxiliatorSetupBitAGate, gate_id_);
    bit_a_future_online_ = message_manager.RegisterReceive(
        1, communication::MessageType::kAuxiliatorOnlineBitAGate, gate_id_);
  }
}

template<typename T>
void BitAGate<T>::EvaluateSetup() {
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto& out_lambda_matrices = matrix_out_wire->GetMutableLambdaMatrices();
  auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
  auto bit_matrix_wire = std::dynamic_pointer_cast<boolean_auxiliator::BitMatrixWire>(parent_[0]);
  assert(bit_matrix_wire);
  auto const& bit_matrix_lambdas1 = bit_matrix_wire->GetLambdas1();
  auto const& bit_matrix_lambdas2 = bit_matrix_wire->GetLambdas2();
  
  size_t u = bit_matrix_wire->GetNumberOfRows();
  size_t v = bit_matrix_wire->GetNumberOfColumns();
  size_t number_of_simd_values = bit_matrix_wire->GetMatrixSimdValues();
  
  switch (my_id) {
    case 0: {
      //RNG shared with party 1
      auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
      //RNG shared with party 2
      auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
      
      std::vector<boost::numeric::ublas::matrix<UInt128>> gamma_tu2 =
        CreateMatrices<UInt128>(u, v, number_of_simd_values);
      //Generate and store gamma_tu1, lambda_z1 into gamma_tu2, out_value_matrices
      SetToRandom(gamma_tu2, out_value_matrices, rng1, gate_id_);
      //Generate and store lambda_z2 into out_lambda_matrices
      SetToRandom(out_lambda_matrices, rng2, gate_id_);
      matrix_out_wire->SetSetupIsReady();

      bit_matrix_wire->GetSetupReadyCondition()->Wait();
      for (size_t s = 0; s != number_of_simd_values; ++s) {
        for(size_t i = 0; i != u; ++i) {
          for(size_t j = 0; j != v; ++j) {
            size_t const index = s*u*v + i*v + j;
            UInt128 lambda_t_extended = UInt128(bit_matrix_lambdas1.Get(index));
            UInt128 lambda_u_extended = UInt128(bit_matrix_lambdas2.Get(index));
            UInt128 gamma_tu_extended = lambda_t_extended * lambda_u_extended;
            triple_.AppendTriple(
              lambda_t_extended, lambda_u_extended, gamma_tu_extended);
            gamma_tu2[s](i, j) = gamma_tu_extended - gamma_tu2[s](i, j);
          }
        }
      }
      backend_.GetAuxiliatorVerifier()->SetReady();

      auto payload = SerializeMatrices(gamma_tu2);
      auto message = communication::BuildMessage(communication::MessageType::kAuxiliatorSetupBitAGate,
                                               gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
      break;
    }
    case 1: {
      //RNG shared with party 0
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      std::vector<boost::numeric::ublas::matrix<UInt128>> gamma_tu1s =
        CreateMatrices<UInt128>(u, v, number_of_simd_values);
      //Generate gamma_tu1, lambda_z1 and store them in 
      //gamma_tu1, out_lambda_matrices respectively
      SetToRandom(gamma_tu1s, out_lambda_matrices, rng0, gate_id_);
      matrix_out_wire->SetSetupIsReady();
      
      bit_matrix_wire->GetSetupReadyCondition()->Wait();
      for (size_t s = 0; s != number_of_simd_values; ++s) {
        for(size_t i = 0; i != u; ++i) {
          for(size_t j = 0; j != v; ++j) {
            size_t const index = s*u*v + i*v + j;
            T lambda_t = T(bit_matrix_lambdas1.Get(index));
            T gamma_tu1 = T(gamma_tu1s[s](i, j));
            UInt128 lambda_t_extended = UInt128(lambda_t);
            UInt128 lambda_u_extended = UInt128(0);
            UInt128 gamma_tu1_extended = gamma_tu1s[s](i, j);
            triple_.AppendTriple(
              lambda_t_extended, lambda_u_extended, gamma_tu1_extended);
            out_value_matrices[s](i, j) = lambda_t - 2*gamma_tu1;
          }
        }
      }
      backend_.GetAuxiliatorVerifier()->SetReady();
      //Now out_value_matrices contain R1
      break;
    }
    case 2: {
      //RNG shared with party 0
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      //Generate and store lambda_z2 into out_lambda_matrices
      SetToRandom(out_lambda_matrices, rng0, gate_id_);
      matrix_out_wire->SetSetupIsReady();
      
      std::vector<boost::numeric::ublas::matrix<UInt128>> gamma_tu2s =
        CreateMatrices<UInt128>(u, v, number_of_simd_values);
      const auto message = bit_a_future_setup_.get();
      const auto payload = communication::GetMessage(message.data())->payload();
      DeserializeMatrices(gamma_tu2s, {payload->Data(), payload->size()});
      bit_matrix_wire->GetSetupReadyCondition()->Wait();
      for (size_t s = 0; s != number_of_simd_values; ++s) {
        for(size_t i = 0; i != u; ++i) {
          for(size_t j = 0; j != v; ++j) {
            size_t const index = s*u*v + i*v + j;
            T lambda_u = T(bit_matrix_lambdas2.Get(index));
            T gamma_tu2 = T(gamma_tu2s[s](i, j));
            UInt128 lambda_t_extended = UInt128(0);
            UInt128 lambda_u_extended = UInt128(lambda_u);
            UInt128 gamma_tu2_extended = gamma_tu2;
            triple_.AppendTriple(
              lambda_t_extended, lambda_u_extended, gamma_tu2_extended);
            out_value_matrices[s](i, j) = lambda_u - 2*gamma_tu2;
          }
        }
      }
      backend_.GetAuxiliatorVerifier()->SetReady();
      //Now out_value_matrices contain R2
      break;
    }
  }
}

template<typename T>
void BitAGate<T>::EvaluateOnline() {
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto bit_matrix_wire = std::dynamic_pointer_cast<boolean_auxiliator::BitMatrixWire>(parent_[0]);
  
  auto& out_lambda_matrices = matrix_out_wire->GetMutableLambdaMatrices();
  auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
  auto& bit_matrix_values = bit_matrix_wire->GetValues();
  
  size_t u = bit_matrix_wire->GetNumberOfRows();
  size_t v = bit_matrix_wire->GetNumberOfColumns();
  size_t number_of_simd_values = bit_matrix_wire->GetMatrixSimdValues();
  WaitSetup();
  assert(setup_is_ready_);
  parent_[0]->GetIsReadyCondition().Wait();

  if (my_id != 0) {
    for (size_t s = 0; s != number_of_simd_values; ++s) {
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          size_t const index = s*u*v + i*v + j;
          //out_value_matrices contain R1 or R2
          //out_lambda_matrices contain lambda_z1 or lambda_z2
          out_value_matrices[s](i, j) = 
            (1 - 2*T(bit_matrix_values.Get(index))) * 
            out_value_matrices[s](i, j) - out_lambda_matrices[s](i, j);
        }
      }
    }
    //Now out_value_matrices contain P1 or P2

    {
      auto payload = SerializeMatrices(out_value_matrices);
      auto message = communication::BuildMessage(
          communication::MessageType::kAuxiliatorOnlineBitAGate, gate_id_, payload);
      communication_layer.SendMessage( (my_id == 1 ? 2 : 1), message.Release());
    }
        
    auto other_party_matrices = CreateMatrices<T>(u, v, number_of_simd_values);
    {
      const auto message = bit_a_future_online_.get();
      const auto payload = communication::GetMessage(message.data())->payload();
      DeserializeMatrices(other_party_matrices, {payload->Data(), payload->size()});
    }
  
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          size_t const index = s*u*v + i*v + j;
          out_value_matrices[s](i, j) += 
            other_party_matrices[s](i, j) + T(bit_matrix_values.Get(index));
        }
      }
    }
  }
}

template <typename T>
auxiliator::SharePointer<T> BitAGate<T>::GetOutputAsAuxiliatorShare() {
  auto wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
  assert(wire);
  return std::make_shared<auxiliator::Share<T>>(wire);
}

template class BitAGate<std::uint8_t>;
template class BitAGate<std::uint16_t>;
template class BitAGate<std::uint32_t>;
template class BitAGate<std::uint64_t>;

template<typename T>
MsbGate<T>::MsbGate(MatrixWirePointer<T> const& matrix_wire)
: Base(matrix_wire->GetBackend()) {
  parent_ = {matrix_wire};
  size_t u = matrix_wire->GetLambdaMatrices()[0].size1();
  size_t v = matrix_wire->GetLambdaMatrices()[0].size2();
  size_t number_of_simd_values = matrix_wire->GetNumberOfSimdValues();
  
  auto& communication_layer = GetCommunicationLayer();
  std::size_t my_id = communication_layer.GetMyId();
  
  switch(my_id) {
    case 0: {
      R1_ = CreateMatrices<T>(u, v, number_of_simd_values);
      break;
    }
    case 1: {
      R1_ = CreateMatrices<T>(u, v, number_of_simd_values);
      R2_ = CreateMatrices<T>(u, v, number_of_simd_values);
      break;
    }
    case 2: {
      R2_ = CreateMatrices<T>(u, v, number_of_simd_values);
      break;
    }
  }
  
  std::vector<boolean_auxiliator::WirePointer> A_wires, B_wires;
  A_wires.reserve(sizeof(T) * CHAR_BIT);
  B_wires.reserve(sizeof(T) * CHAR_BIT);
  for(size_t s = 0; s != sizeof(T) * CHAR_BIT; ++s) {
    A_wires.emplace_back(
      std::make_shared<boolean_auxiliator::Wire>(
        backend_,
        BitVector<>(u*v*number_of_simd_values, false), 
        BitVector<>(u*v*number_of_simd_values, false), 
        BitVector<>(u*v*number_of_simd_values, false)));
    B_wires.emplace_back(
      std::make_shared<boolean_auxiliator::Wire>(
        backend_,
        BitVector<>(u*v*number_of_simd_values, false), 
        BitVector<>(u*v*number_of_simd_values, false), 
        BitVector<>(u*v*number_of_simd_values, false)));
  }
  A_ = ShareWrapper(std::make_shared<boolean_auxiliator::Share>(std::move(A_wires)));
  B_ = ShareWrapper(std::make_shared<boolean_auxiliator::Share>(std::move(B_wires)));
  PPA_ = MsbAdd(A_, B_);
  
  auto& ppa_wires = PPA_->GetWires();
  assert(1 == ppa_wires.size());
  auto ppa_wire = std::dynamic_pointer_cast<boolean_auxiliator::Wire>(ppa_wires[0]);
  assert(ppa_wire);
  assert(u*v*number_of_simd_values == std::dynamic_pointer_cast<boolean_auxiliator::Wire>(ppa_wire)->GetValues().GetSize());
  assert(u*v*number_of_simd_values == std::dynamic_pointer_cast<boolean_auxiliator::Wire>(ppa_wire)->GetLambdas1().GetSize());
  assert(u*v*number_of_simd_values == std::dynamic_pointer_cast<boolean_auxiliator::Wire>(ppa_wire)->GetLambdas2().GetSize());
  output_wires_ =
    {GetRegister().template EmplaceWire<boolean_auxiliator::BitMatrixWire>(
       backend_, ppa_wire->GetValues(), 
       ppa_wire->GetLambdas1(), ppa_wire->GetLambdas2(),
       u, v, number_of_simd_values)};
  
  if (my_id == 2) {
    auto& message_manager = communication_layer.GetMessageManager();
    msb_future_online_ = message_manager.RegisterReceive(
        1, communication::MessageType::kAuxiliatorOnlineMsbGate, gate_id_);
  }
}

template<typename T>
void MsbGate<T>::EvaluateSetup() {
  auto& communication_layer = GetCommunicationLayer();
  std::size_t my_id = communication_layer.GetMyId();
  auto matrix_in_wire = std::dynamic_pointer_cast<MatrixWire<T>>(parent_[0]);
  assert(matrix_in_wire);
  auto const& matrix_in_lambdas = matrix_in_wire->GetMutableLambdaMatrices();
  auto out_wire = std::dynamic_pointer_cast<boolean_auxiliator::BitMatrixWire>(output_wires_[0]);
  assert(out_wire);

  size_t u = matrix_in_lambdas[0].size1();
  size_t v = matrix_in_lambdas[0].size2();
  size_t number_of_simd_values = matrix_in_wire->GetNumberOfSimdValues();
  
  if(my_id == 0 || my_id == 2) {
    matrix_in_wire->GetSetupReadyCondition()->Wait();
  }
  
  //Setting the wires before generating randomness should increase parallelization here,
  //as we have to wait for the PPA circuit to be completed, to get our lambdas
  for(size_t k = 0; k != sizeof(T) * CHAR_BIT; ++k) {
    auto a_wire = std::dynamic_pointer_cast<boolean_auxiliator::Wire>(A_->GetWires()[k]);
    auto b_wire = std::dynamic_pointer_cast<boolean_auxiliator::Wire>(B_->GetWires()[k]);
    assert(a_wire);
    assert(b_wire);
    auto& a_lambdas1 = a_wire->GetMutableLambdas1();
    auto& b_lambdas2 = b_wire->GetMutableLambdas2();
    assert(a_lambdas1.GetSize() == u*v*number_of_simd_values);
    assert(b_lambdas2.GetSize() == u*v*number_of_simd_values);
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          T a_lambda1 = 0;
          T b_lambda2 = 0;
          switch(my_id) {
            case 0: {
              a_lambda1 = (R1_[s](i, j) >> k) & 0x1;
              b_lambda2 = (matrix_in_lambdas[s](i, j) >> k) & 0x1;
              break;
            }
            case 1: {
              a_lambda1 = (R1_[s](i, j) >> k) & 0x1;
              break;
            }
            case 2: {
              b_lambda2 = (matrix_in_lambdas[s](i, j) >> k) & 0x1;
              break;
            }
          }
          size_t const index = s*u*v + i*v + j;
          a_lambdas1.Set(bool(a_lambda1), index);
          b_lambdas2.Set(bool(b_lambda2), index);
        }
      }
    }
    a_wire->SetSetupIsReady();
    b_wire->SetSetupIsReady();
  }
  
  switch(my_id) {
    case 0: {
      //RNG shared with party 1
      auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
      SetToRandom(R1_, rng1, gate_id_);
      break;
    }
    case 1: {
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      SetToRandom(R1_, rng0, gate_id_);
      break;
    }
    case 2: {
      break;
    }
  }
  
  auto ppa_wire = std::dynamic_pointer_cast<boolean_auxiliator::Wire>(PPA_->GetWires()[0]);
  ppa_wire->GetSetupReadyCondition()->Wait();
  out_wire->GetMutableLambdas1() = std::move(ppa_wire->GetMutableLambdas1());
  out_wire->GetMutableLambdas2() = std::move(ppa_wire->GetMutableLambdas2());
  //We immediately invert the lambdas of the wire, since we only use msb gate in ReLU
  if(my_id != 1) {
    out_wire->GetMutableLambdas2().Invert();
  }
  out_wire->SetSetupIsReady();
}

template<typename T>
void MsbGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  
  auto& communication_layer = GetCommunicationLayer();
  std::size_t my_id = communication_layer.GetMyId();
  
  auto matrix_in_wire = std::dynamic_pointer_cast<MatrixWire<T>>(parent_[0]);
  assert(matrix_in_wire);
  auto const& matrix_in_lambdas = matrix_in_wire->GetMutableLambdaMatrices();
  auto const& matrix_in_values = matrix_in_wire->GetMutableValueMatrices();

  size_t u = matrix_in_lambdas[0].size1();
  size_t v = matrix_in_lambdas[0].size2();
  size_t number_of_simd_values = matrix_in_wire->GetNumberOfSimdValues();
  auto& ppa_wires = PPA_->GetWires();
  matrix_in_wire->GetIsReadyCondition().Wait();
  
  if(my_id == 1) {
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          R2_[s](i, j) = (matrix_in_values[s](i, j) + matrix_in_lambdas[s](i, j)) ^ R1_[s](i, j);
        }
      }
    }
    auto payload = SerializeMatrices(R2_);
    auto message = 
      communication::BuildMessage(
        communication::MessageType::kAuxiliatorOnlineMsbGate, gate_id_, payload);
    communication_layer.SendMessage(2, message.Release());
  } else if(my_id == 2) {
    const auto message = msb_future_online_.get();
    const auto payload = communication::GetMessage(message.data())->payload();
    //Receive and store R2
    DeserializeMatrices(R2_, {payload->Data(), payload->size()});
  }
  
  //We set the lambdas wires for the inner PPA
  //The matrices M_s will be vectorized like this:
  //(M_0_0_0, M_0_0_1, ..., M_0_0_v, M_0_1_0, ..., M_0_u_v, M_1_0_0,..., M_s_u_v)
  for(size_t k = 0; k != sizeof(T) * CHAR_BIT; ++k) {
    auto a_wire = std::dynamic_pointer_cast<boolean_auxiliator::Wire>(A_->GetWires()[k]);
    auto b_wire = std::dynamic_pointer_cast<boolean_auxiliator::Wire>(B_->GetWires()[k]);
    assert(a_wire);
    assert(b_wire);
    //a_value is already set to 0
    auto& a_values = a_wire->GetMutableValues();
    assert(a_values.GetSize() == u*v*number_of_simd_values);
    if(my_id != 0) {
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        for(size_t i = 0; i != u; ++i) {
          for(size_t j = 0; j != v; ++j) {
            size_t const index = s*u*v + i*v + j;
            T a_value = (R2_[s](i, j) >> k) & 0x1;
            a_values.Set(bool(a_value), index);
          }
        }
      }
    }
    a_wire->SetOnlineFinished();
    b_wire->SetOnlineFinished();
  }
  auto ppa_wire = std::dynamic_pointer_cast<boolean_auxiliator::Wire>(ppa_wires[0]);
  ppa_wire->GetIsReadyCondition().Wait();
  auto out_wire = std::dynamic_pointer_cast<boolean_auxiliator::BitMatrixWire>(output_wires_[0]);
  assert(out_wire);
  
  out_wire->GetMutableValues() = std::move(ppa_wire->GetMutableValues());
}

template<typename T>
boolean_auxiliator::SharePointer MsbGate<T>::GetOutputAsBooleanAuxiliatorShare() {
  return std::make_shared<boolean_auxiliator::Share>(output_wires_);
}

template class MsbGate<std::uint8_t>;
template class MsbGate<std::uint16_t>;
template class MsbGate<std::uint32_t>;
template class MsbGate<std::uint64_t>;

template <typename T>
MultiplicationGate<T>::MultiplicationGate(const auxiliator::WirePointer<T>& a,
                                          const auxiliator::WirePointer<T>& b)
: TwoGate(a->GetBackend()), 
  triple_(backend_.GetAuxiliatorVerifier()->ReserveTriples128(a->GetNumberOfSimdValues())) {
  assert(a->GetNumberOfSimdValues() == b->GetNumberOfSimdValues());
  parent_a_ = {std::move(a)};
  parent_b_ = {std::move(b)};

  std::vector<typename auxiliator::Wire<T>::value_type> v(parent_a_[0]->GetNumberOfSimdValues());
  auto w = GetRegister().template EmplaceWire<auxiliator::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};

  std::size_t my_id{GetCommunicationLayer().GetMyId()};
  auto& message_manager{backend_.GetCommunicationLayer().GetMessageManager()};
  if (my_id == 1) {
    multiply_future_online_ = message_manager.RegisterReceive(
        2, communication::MessageType::kAuxiliatorOnlineMultiplyGate, gate_id_);
  } else if (my_id == 2) {
    multiply_future_setup_ = message_manager.RegisterReceive(
        0, communication::MessageType::kAuxiliatorSetupMultiplyGate, gate_id_);
    multiply_future_online_ = message_manager.RegisterReceive(
        1, communication::MessageType::kAuxiliatorOnlineMultiplyGate, gate_id_);
  }

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_[0]->GetWireId(), parent_b_[0]->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an auxiliator::MultiplicationGate with following properties: {}", gate_info));
  }
}

template <typename T>
void MultiplicationGate<T>::EvaluateSetup() {
  using communication::MessageType::kAuxiliatorSetupMultiplyGate;
  auto& communication_layer = GetCommunicationLayer();
  auto const my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(parent_b_[0]);
  assert(b_wire);
  auto const& a_values = a_wire->GetValues();
  auto const& b_values = b_wire->GetValues();
  auto& out_values = out_wire->GetMutableValues();
  size_t const number_of_simd_values = a_wire->GetNumberOfSimdValues();

  switch (my_id) {
    case 0: {
      auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
      auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
      std::vector<uint8_t> randoms1 = 
        rng1.template GetUnsigned<uint8_t>(
          gate_id_, 
          number_of_simd_values * sizeof(T) + number_of_simd_values * sizeof(UInt128)
        );
      std::vector<uint8_t> randoms2 = 
        rng2.template GetUnsigned<uint8_t>(
          gate_id_, 
          number_of_simd_values * sizeof(T));

      for(size_t i = 0; i != number_of_simd_values; ++i) {
        size_t random_offset = i * sizeof(T);
        auto& out = out_values[i];
        memcpy(&out.lambda1, &randoms1[random_offset], sizeof(T));
        memcpy(&out.lambda2, &randoms2[random_offset], sizeof(T));
      }
      out_wire->SetSetupIsReady();

      std::vector<UInt128> message_gamma_ab_2;
      message_gamma_ab_2.reserve(number_of_simd_values);
      a_wire->GetSetupReadyCondition()->Wait();
      b_wire->GetSetupReadyCondition()->Wait();
      for (size_t i = 0; i != number_of_simd_values; ++i) {
        size_t extended_random_offset = number_of_simd_values * sizeof(T) + i * sizeof(UInt128);
        
        auto& a = a_values[i];
        auto& b = b_values[i];

        UInt128 gamma_ab_1;
        memcpy(&gamma_ab_1, &randoms1[extended_random_offset], sizeof(UInt128));
        UInt128 lambda_a = UInt128(a.lambda1) + UInt128(a.lambda2);
        UInt128 lambda_b = UInt128(b.lambda1) + UInt128(b.lambda2);
        UInt128 gamma_ab = lambda_a * lambda_b;
        UInt128 gamma_ab_2 = gamma_ab - gamma_ab_1;
        message_gamma_ab_2.emplace_back(gamma_ab_2);
        triple_.AppendTriple(lambda_a, lambda_b, gamma_ab);
      }
      backend_.GetAuxiliatorVerifier()->SetReady();
      assert(message_gamma_ab_2.size() == out_values.size());

      auto payload = ToByteVector<UInt128>(message_gamma_ab_2);
      auto message = communication::BuildMessage(kAuxiliatorSetupMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
      break;
    }
    case 1: {
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      std::vector<uint8_t> randoms0 = 
        rng0.template GetUnsigned<uint8_t>(
          gate_id_, 
          number_of_simd_values * sizeof(T) + number_of_simd_values * sizeof(UInt128)
        );
        
      for (size_t i = 0; i != number_of_simd_values; ++i) {
        size_t random_offset = i * sizeof(T);
        auto& out = out_values[i];
        memcpy(&out.lambda1, &randoms0[random_offset], sizeof(T));
      }
      out_wire->SetSetupIsReady();

      a_wire->GetSetupReadyCondition()->Wait();
      b_wire->GetSetupReadyCondition()->Wait();
      for (size_t i = 0; i != number_of_simd_values; ++i) {
        size_t extended_random_offset = number_of_simd_values * sizeof(T) + i * sizeof(UInt128);
        UInt128 gamma_ab_1;
        memcpy(&gamma_ab_1, &randoms0[extended_random_offset], sizeof(UInt128));
        auto& out = out_values[i];
        //We store gamma_ab_1 in the free out.lambda2 space
        out.lambda2 = T(gamma_ab_1);
        auto& a = a_values[i];
        auto& b = b_values[i];
        UInt128 lambda_a_1 = a.lambda1;
        UInt128 lambda_b_1 = b.lambda1;
        triple_.AppendTriple(lambda_a_1, lambda_b_1, gamma_ab_1);
      }
      backend_.GetAuxiliatorVerifier()->SetReady();
      break;
    }
    case 2: {
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      std::vector<uint8_t> randoms0 = 
        rng0.template GetUnsigned<uint8_t>(gate_id_, number_of_simd_values * sizeof(T));
      for (auto i = 0u; i != number_of_simd_values; ++i) {
        size_t random_offset = i * sizeof(T);
        auto& out = out_values[i];
        memcpy(&out.lambda2, &randoms0[random_offset], sizeof(T));
      }
      out_wire->SetSetupIsReady();

      const auto message = multiply_future_setup_.get();
      const auto payload = 
        communication::GetMessage(message.data())->payload();
      std::vector<UInt128> message_gamma_ab_2 = 
        FromByteVector<UInt128>({payload->Data(), payload->size()});
      assert(message_gamma_ab_2.size() == number_of_simd_values);

      a_wire->GetSetupReadyCondition()->Wait();
      b_wire->GetSetupReadyCondition()->Wait();
      for (auto i = 0u; i != number_of_simd_values; ++i) {
        auto& a = a_values[i];
        auto& b = b_values[i];
        UInt128 lambda_a_2 = a.lambda2;
        UInt128 lambda_b_2 = b.lambda2;
        UInt128 gamma_ab_2 = message_gamma_ab_2[i];
        auto& out = out_values[i];
        // We store gamma_ab_2 in the free out.lambda1 space
        out.lambda1 = T(gamma_ab_2);
        triple_.AppendTriple(lambda_a_2, lambda_b_2, gamma_ab_2);
      }
      backend_.GetAuxiliatorVerifier()->SetReady();
      break;
    }
  }
}

template <typename T>
void MultiplicationGate<T>::EvaluateOnline() {
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();

  auto out_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(parent_b_[0]);
  assert(b_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();

  if (my_id != 0) {
    switch (my_id) {
      case 1: {
        for (auto i = 0u; i != out_values.size(); ++i) {
          auto& out = out_values[i];
          auto const& a = a_values[i];
          auto const& b = b_values[i];
          auto const& gamma_ab_1 = out.lambda2;

          out.value = a.value * b.lambda1 + 
                      a.lambda1 * b.value + 
                      gamma_ab_1 - out.lambda1;
        }

        std::vector<T> message_values;
        message_values.reserve(out_values.size());
        for (auto i = 0u; i != out_values.size(); ++i) {
          message_values.emplace_back(out_values[i].value);
        }
        assert(message_values.size() == out_values.size());

        {
          auto payload = ToByteVector<T>(message_values);
          auto message{communication::BuildMessage(
              communication::MessageType::kAuxiliatorOnlineMultiplyGate, gate_id_, payload)};
          communication_layer.SendMessage(2, message.Release());
        }
        const auto multiply_message{multiply_future_online_.get()};
        const auto payload{communication::GetMessage(multiply_message.data())->payload()};
        message_values = FromByteVector<T>({payload->Data(), payload->size()});
        assert(message_values.size() == out_values.size());

        for (auto i = 0u; i != out_values.size(); ++i) {
          out_values[i].value += message_values[i];
        }
        break;
      }
      case 2: {
        for (auto i = 0u; i != out_values.size(); ++i) {
          auto& out = out_values[i];
          auto const& a = a_values[i];
          auto const& b = b_values[i];
          auto const& gamma_ab_2 = out.lambda1;

          out.value = a.value * b.value + 
                      a.value * b.lambda2 + 
                      a.lambda2 * b.value +
                      gamma_ab_2 - out.lambda2;
        }

        std::vector<T> message_values;
        message_values.reserve(out_values.size());
        for (auto i = 0u; i != out_values.size(); ++i) {
          message_values.emplace_back(out_values[i].value);
        }
        assert(message_values.size() == out_values.size());

        {
          auto payload = ToByteVector<T>(message_values);
          auto message{communication::BuildMessage(
              communication::MessageType::kAuxiliatorOnlineMultiplyGate, gate_id_, payload)};
          communication_layer.SendMessage(1, message.Release());
        }

        const auto message{multiply_future_online_.get()};
        const auto payload{communication::GetMessage(message.data())->payload()};
        message_values = FromByteVector<T>({payload->Data(), payload->size()});
        assert(message_values.size() == out_values.size());

        for (auto i = 0u; i != out_values.size(); ++i) {
          out_values[i].value += message_values[i];
        }
        break;
      }
    }
  }
  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated auxiliator::MultiplicationGate with id#{}", gate_id_));
  }
}

template <typename T>
auxiliator::SharePointer<T> MultiplicationGate<T>::GetOutputAsAuxiliatorShare() {
  auto wire = std::dynamic_pointer_cast<auxiliator::Wire<T>>(output_wires_[0]);
  assert(wire);
  return std::make_shared<auxiliator::Share<T>>(wire);
}

template class MultiplicationGate<std::uint8_t>;
template class MultiplicationGate<std::uint16_t>;
template class MultiplicationGate<std::uint32_t>;
template class MultiplicationGate<std::uint64_t>;

namespace {

template<typename T>
std::vector<boost::numeric::ublas::matrix<UInt128>> Convert128(
  std::vector<boost::numeric::ublas::matrix<T>> const& mats) {
  size_t number_of_simd_values = mats.size();
  std::vector<boost::numeric::ublas::matrix<UInt128>> result;
  result.reserve(number_of_simd_values);
  
  for(size_t s = 0; s != number_of_simd_values; ++s) {
    size_t m = mats[s].size1();
    size_t n = mats[s].size2();
    result.emplace_back(m, n);
    for(size_t i = 0; i != m; ++i) {
      for(size_t j = 0; j != n; ++j) {
        result[s](i, j) = UInt128(mats[s](i, j));
      }
    }
  }
  
  return result;
}

template<typename T>
std::vector<boost::numeric::ublas::matrix<UInt128>> Convert128(
  std::vector<boost::numeric::ublas::matrix<T>> const& mats, 
  std::vector<boost::numeric::ublas::matrix<T>> const& other_mats) {
  size_t number_of_simd_values = mats.size();
  assert(other_mats.size() == number_of_simd_values);
  std::vector<boost::numeric::ublas::matrix<UInt128>> result;
  result.reserve(number_of_simd_values);
  
  for(size_t s = 0; s != number_of_simd_values; ++s) {
    size_t m = mats[s].size1();
    size_t n = mats[s].size2();
    assert(other_mats[s].size1() == m);
    assert(other_mats[s].size2() == n);
    result.emplace_back(m, n);
    for(size_t i = 0; i != m; ++i) {
      for(size_t j = 0; j != n; ++j) {
        result[s](i, j) = UInt128(mats[s](i, j)) + UInt128(other_mats[s](i, j));
      }
    }
  }
  
  return result;
}

template<typename T>
void ConvertBack(
  std::vector<boost::numeric::ublas::matrix<T>>& output_matrix,
  std::vector<boost::numeric::ublas::matrix<UInt128>> const& matrix128) {
  size_t number_of_simd_values = output_matrix.size();
  assert(matrix128.size() == number_of_simd_values);
  
  for(size_t s = 0; s != number_of_simd_values; ++s) {
    size_t m = output_matrix[s].size1();
    size_t n = output_matrix[s].size2();
    assert(matrix128[s].size1() == m);
    assert(matrix128[s].size2() == n);
    
    for(size_t i = 0; i != m; ++i) {
      for(size_t j = 0; j != n; ++j) {
        output_matrix[s](i, j) = T(matrix128[s](i, j));
      }
    }
  }
}

}  // namespace (anonymous) 

template<typename T>
MatrixMultiplicationGate<T>::MatrixMultiplicationGate(
  MatrixWirePointer<T> matrix_a, MatrixWirePointer<T> matrix_b)
: TwoGate(matrix_a->GetBackend()),
  triple_(backend_.GetAuxiliatorVerifier()->ReserveMatrixTriples128(matrix_a->GetNumberOfSimdValues())) {
  
  assert(matrix_a->GetNumberOfSimdValues() == matrix_b->GetNumberOfSimdValues());
  parent_a_ = {matrix_a};
  parent_b_ = {matrix_b};
  assert(matrix_a->GetLambdaMatrices()[0].size2() == matrix_b->GetLambdaMatrices()[0].size1());
  
  size_t u = matrix_a->GetLambdaMatrices()[0].size1();
  size_t v = matrix_b->GetLambdaMatrices()[0].size2();
  size_t number_of_simd_values = matrix_a->GetNumberOfSimdValues();

  auto w = GetRegister().template EmplaceWire<auxiliator::MatrixWire<T>>(backend_, u, v, number_of_simd_values);
  output_wires_ = {std::move(w)};

  std::size_t my_id = GetCommunicationLayer().GetMyId();
  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  //P0 never receives anything
  if (my_id == 1) {
    matrix_multiply_future_online_ = message_manager.RegisterReceive(
        2, communication::MessageType::kAuxiliatorOnlineMultiplyGate, gate_id_);
  } else if (my_id == 2) {
    matrix_multiply_future_setup_ = message_manager.RegisterReceive(
        0, communication::MessageType::kAuxiliatorSetupMultiplyGate, gate_id_);
    matrix_multiply_future_online_ = message_manager.RegisterReceive(
        1, communication::MessageType::kAuxiliatorOnlineMultiplyGate, gate_id_);
  }

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_[0]->GetWireId(), parent_b_[0]->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an auxiliator::MatrixMultiplicationGate with following properties: {}", gate_info));
    }
}

template<typename T>
void MatrixMultiplicationGate<T>::EvaluateSetup() {
  using boost::numeric::ublas::matrix;
  using communication::MessageType::kAuxiliatorSetupMultiplyGate;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(parent_a_[0]);
  assert(matrix_a_wire);
  auto matrix_b_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(parent_b_[0]);
  assert(matrix_b_wire);
  
  auto& a_lambda_matrices = matrix_a_wire->GetMutableLambdaMatrices();
  auto& b_lambda_matrices = matrix_b_wire->GetMutableLambdaMatrices();
  auto& a_value_matrices = matrix_a_wire->GetMutableValueMatrices();
  auto& b_value_matrices = matrix_b_wire->GetMutableValueMatrices();
  auto& out_lambda_matrices = matrix_out_wire->GetMutableLambdaMatrices();
  auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
  
  size_t u = out_lambda_matrices[0].size1();
  size_t v = out_lambda_matrices[0].size2();
  size_t number_of_simd_values = matrix_a_wire->GetNumberOfSimdValues();
  
  switch (my_id) {
    case 0: {
      //RNG shared with party 1
      auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
      //RNG shared with party 2
      auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);

      std::vector<matrix<UInt128>> gamma_ab2
        = CreateMatrices<UInt128>(u, v, number_of_simd_values);
      //Generate and store gamma_ab1, lambda_z1 into gamma_ab2, out_value_matrices
      SetToRandom(gamma_ab2, out_value_matrices, rng1, gate_id_);
      //Generate and store lambda_z2 into out_lambda_matrices
      SetToRandom(out_lambda_matrices, rng2, gate_id_);
      matrix_out_wire->SetSetupIsReady();

      matrix_a_wire->GetSetupReadyCondition()->Wait();
      matrix_b_wire->GetSetupReadyCondition()->Wait();
      std::vector<matrix<UInt128>> lambda_as 
        = Convert128(a_lambda_matrices, a_value_matrices);
      std::vector<matrix<UInt128>> lambda_bs 
        = Convert128(b_lambda_matrices, b_value_matrices);
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        auto& lambda_a = lambda_as[s];
        auto& lambda_b = lambda_bs[s];
        matrix<UInt128> gamma_ab = prod(lambda_a, lambda_b);
        gamma_ab2[s] = gamma_ab - gamma_ab2[s];
        triple_.AppendTriple(lambda_a, lambda_b, gamma_ab);
      }
      backend_.GetAuxiliatorVerifier()->SetReady();
      auto payload = SerializeMatrices(gamma_ab2);
      auto message = 
        communication::BuildMessage(kAuxiliatorSetupMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
      break;
    }
    case 1: {
      //RNG shared with party 0
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      std::vector<matrix<UInt128>> gamma_ab1_extended
        = CreateMatrices<UInt128>(u, v, number_of_simd_values);
      SetToRandom(gamma_ab1_extended, out_lambda_matrices, rng0, gate_id_);
      matrix_out_wire->SetSetupIsReady();
      
      matrix_a_wire->GetSetupReadyCondition()->Wait();
      matrix_b_wire->GetSetupReadyCondition()->Wait();
      std::vector<matrix<UInt128>> lambda_as = Convert128(a_lambda_matrices);
      std::vector<matrix<UInt128>> lambda_bs = Convert128(b_lambda_matrices);
      
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        triple_.AppendTriple(lambda_as[s], lambda_bs[s], gamma_ab1_extended[s]);
      }
      backend_.GetAuxiliatorVerifier()->SetReady();
      //We store gamma_ab1 in out_value_matrices
      ConvertBack(out_value_matrices, gamma_ab1_extended);
      break;
    }
    case 2: {
      //RNG shared with party 0
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      //Generate and store lambda_z2 into out_lambda_matrices
      SetToRandom(out_lambda_matrices, rng0, gate_id_);
      matrix_out_wire->SetSetupIsReady();
      
      std::vector<matrix<UInt128>> gamma_ab2_extended 
        = CreateMatrices<UInt128>(u, v, number_of_simd_values);
      const auto message = matrix_multiply_future_setup_.get();
      const auto payload = communication::GetMessage(message.data())->payload();
      DeserializeMatrices(gamma_ab2_extended, {payload->Data(), payload->size()});
      matrix_a_wire->GetSetupReadyCondition()->Wait();
      matrix_b_wire->GetSetupReadyCondition()->Wait();
      std::vector<matrix<UInt128>> lambda_as = Convert128(a_lambda_matrices);
      std::vector<matrix<UInt128>> lambda_bs = Convert128(b_lambda_matrices);
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        triple_.AppendTriple(lambda_as[s], lambda_bs[s], gamma_ab2_extended[s]);
      }
      backend_.GetAuxiliatorVerifier()->SetReady();
      //We store gamma_ab2 in out_value_matrices
      ConvertBack(out_value_matrices, gamma_ab2_extended);
      break;
    }
  }
}

template<typename T>
void MatrixMultiplicationGate<T>::EvaluateOnline() {
  using boost::numeric::ublas::noalias;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(parent_a_[0]);
  assert(matrix_a_wire);
  auto matrix_b_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(parent_b_[0]);
  assert(matrix_b_wire);
  
  auto& a_lambda_matrices = matrix_a_wire->GetMutableLambdaMatrices();
  auto& a_value_matrices = matrix_a_wire->GetMutableValueMatrices();
  auto& b_lambda_matrices = matrix_b_wire->GetMutableLambdaMatrices();
  auto& b_value_matrices = matrix_b_wire->GetMutableValueMatrices();
  auto& out_lambda_matrices = matrix_out_wire->GetMutableLambdaMatrices();
  auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
  
  size_t u = out_lambda_matrices[0].size1();
  size_t v = out_lambda_matrices[0].size2();
  size_t number_of_simd_values = matrix_a_wire->GetNumberOfSimdValues();
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();

  if (my_id != 0) {
    for (size_t s = 0; s != number_of_simd_values; ++s) {
      //out_value_matrices contain gamma_ab_1 or gamma_ab_2 and
      //out_lambda_matrices contain lambda_z1 or lambda_z2
      noalias(out_value_matrices[s]) += 
        prod(a_value_matrices[s], b_lambda_matrices[s]) +
        prod(a_lambda_matrices[s], b_value_matrices[s]) -
        out_lambda_matrices[s];
    }

    {
      auto payload = SerializeMatrices(out_value_matrices);
      auto message = communication::BuildMessage(
          communication::MessageType::kAuxiliatorOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage( (my_id == 1 ? 2 : 1), message.Release());
    }
        
    auto other_party_matrices = CreateMatrices<T>(u, v, number_of_simd_values);
    {
      const auto message = matrix_multiply_future_online_.get();
      const auto payload = communication::GetMessage(message.data())->payload();
      DeserializeMatrices(other_party_matrices, {payload->Data(), payload->size()});
    }
  
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      noalias(out_value_matrices[s]) += 
        other_party_matrices[s] + prod(a_value_matrices[s], b_value_matrices[s]);
    }
  }
  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated auxiliator::MatrixMultiplicationGate with id#{}", gate_id_));
  }
}

template <typename T>
auxiliator::SharePointer<T> MatrixMultiplicationGate<T>::GetOutputAsAuxiliatorShare() {
  auto wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
  assert(wire);
  return std::make_shared<auxiliator::Share<T>>(wire);
}

template class MatrixMultiplicationGate<std::uint8_t>;
template class MatrixMultiplicationGate<std::uint16_t>;
template class MatrixMultiplicationGate<std::uint32_t>;
template class MatrixMultiplicationGate<std::uint64_t>;


namespace fixed_point {
    
namespace {
    
constexpr bool checkSignedShift() {
  uint64_t unsigned_number = -2;
  int64_t signed_number = unsigned_number;
  return (signed_number >> 1) == -1;
}

static_assert(checkSignedShift(), "Signed shift is not supported on this platform");

template<typename T>
void Truncate(boost::numeric::ublas::matrix<T>& m, unsigned precision) {
  for(size_t i = 0; i != m.size1(); ++i) {
    for(size_t j = 0; j != m.size2(); ++j) {
      T& element = m(i, j);
      std::make_signed_t<T> signed_element = element;
      signed_element >>= precision;
      element = signed_element;
    }
  }
}

} // namespace (anonymous)

template<typename T>
MatrixConstantMultiplicationGate<T>::MatrixConstantMultiplicationGate(
  T constant, MatrixWirePointer<T> matrix_a, unsigned precision)
: Base(matrix_a->GetBackend()), constant_(constant), precision_(precision) {
  size_t number_of_simd_values = matrix_a->GetNumberOfSimdValues();
  size_t u = matrix_a->GetLambdaMatrices()[0].size1();
  size_t v = matrix_a->GetLambdaMatrices()[0].size2();
  parent_a_ = std::move(matrix_a);

  auto w = GetRegister().template EmplaceWire<auxiliator::MatrixWire<T>>(
             backend_, u, v, number_of_simd_values);
  output_wires_ = {std::move(w)};

  std::size_t my_id = GetCommunicationLayer().GetMyId();
  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  //Only P1 receives messages during setup phase
  if (my_id == 1) {
    matrix_multiply_future_ = message_manager.RegisterReceive(
        2, communication::MessageType::kAuxiliatorSetupMultiplyGate, gate_id_);
  }
  //Only P2 receives messages during online phase
  if (my_id == 2) {
    matrix_multiply_future_ = message_manager.RegisterReceive(
        1, communication::MessageType::kAuxiliatorOnlineMultiplyGate, gate_id_);
  }
}

template<typename T>
void MatrixConstantMultiplicationGate<T>::EvaluateSetup() {
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto& out_lambda_matrices = matrix_out_wire->GetMutableLambdaMatrices();
  auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
  
  switch (my_id) {
    case 0: {
      //RNG shared with party 1
      auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
      auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
      //Generate and store lambda_z1 into out_lambda matrices
      SetToRandom(out_value_matrices, rng1, gate_id_);
      //Generate and store lambda_z2 into out_lambda matrices
      SetToRandom(out_lambda_matrices, rng2, gate_id_);
      matrix_out_wire->SetSetupIsReady();
      break;
    }
    case 1: {
      //RNG shared with party 0
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      //Generate and store lambda_z1 into out_lambda matrices
      SetToRandom(out_lambda_matrices, rng0, gate_id_);
      matrix_out_wire->SetSetupIsReady();
      
      const auto message = matrix_multiply_future_.get();
      const auto payload = communication::GetMessage(message.data())->payload();
      //Receive and store P2 into out_value_matrices
      DeserializeMatrices(out_value_matrices, {payload->Data(), payload->size()});
      break;
    }
    case 2: {
      //RNG shared with party 0
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      //Generate and store lambda_z2 into out_lambda_matrices
      SetToRandom(out_lambda_matrices, rng0, gate_id_);
      matrix_out_wire->SetSetupIsReady();

      parent_a_->GetSetupReadyCondition()->Wait();
      size_t number_of_simd_values = parent_a_->GetNumberOfSimdValues();
      auto& a_lambda_matrices = parent_a_->GetMutableLambdaMatrices();
      for (size_t s = 0; s != number_of_simd_values; ++s) {
        noalias(out_value_matrices[s]) = constant_ * a_lambda_matrices[s];
        Truncate(out_value_matrices[s], precision_);
        noalias(out_value_matrices[s]) -= out_lambda_matrices[s];
      }
      //Now P2 is in out_value_matrices.

      auto payload = SerializeMatrices(out_value_matrices);
      auto message = communication::BuildMessage(
                       communication::MessageType::kAuxiliatorSetupMultiplyGate,
                       gate_id_, 
                       payload);
      communication_layer.SendMessage(1, message.Release());
      break;
    }
  }
}

template<typename T>
void MatrixConstantMultiplicationGate<T>::EvaluateOnline() {
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  
  auto& a_value_matrices = parent_a_->GetValueMatrices();
  auto& a_lambda_matrices = parent_a_->GetLambdaMatrices();
  auto const& out_lambda_matrices = matrix_out_wire->GetLambdaMatrices();
  auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
  
  size_t number_of_simd_values = parent_a_->GetNumberOfSimdValues();
  size_t u = a_value_matrices[0].size1();
  size_t v = a_value_matrices[0].size2();
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_->GetIsReadyCondition().Wait();

  switch (my_id) {
    case 1: {
      auto P1 = CreateMatrices<T>(u, v, number_of_simd_values);
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        noalias(P1[s]) = constant_ * (a_value_matrices[s] + a_lambda_matrices[s]);
        Truncate(P1[s], precision_);
        noalias(P1[s]) -= out_lambda_matrices[s];
        noalias(out_value_matrices[s]) += P1[s];
      }
      auto payload = SerializeMatrices(P1);
      auto message = communication::BuildMessage(
                       communication::MessageType::kAuxiliatorOnlineMultiplyGate,
                       gate_id_, 
                       payload);
      communication_layer.SendMessage(2, message.Release());
      break;
    }
    case 2: {
      const auto message = matrix_multiply_future_.get();
      const auto payload = communication::GetMessage(message.data())->payload();
      auto P1 = CreateMatrices<T>(u, v, number_of_simd_values);
      //Receive and store P1 into out_value_matrices
      DeserializeMatrices(P1, {payload->Data(), payload->size()});
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        noalias(out_value_matrices[s]) += P1[s];
      }
      break;
    }
  }
}

template <typename T>
auxiliator::SharePointer<T> MatrixConstantMultiplicationGate<T>::GetOutputAsAuxiliatorShare() {
  auto wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
  assert(wire);
  return std::make_shared<auxiliator::Share<T>>(wire);
}

template class MatrixConstantMultiplicationGate<std::uint8_t>;
template class MatrixConstantMultiplicationGate<std::uint16_t>;
template class MatrixConstantMultiplicationGate<std::uint32_t>;
template class MatrixConstantMultiplicationGate<std::uint64_t>;

template<typename T>
MatrixMultiplicationGate<T>::MatrixMultiplicationGate(
  MatrixWirePointer<T> matrix_a, MatrixWirePointer<T> matrix_b, unsigned precision)
: TwoGate(matrix_a->GetBackend()),
  triple_(backend_.GetAuxiliatorVerifier()->ReserveMatrixTriples128(matrix_a->GetNumberOfSimdValues())),
  precision_(precision) {
  
  assert(matrix_a->GetNumberOfSimdValues() == matrix_b->GetNumberOfSimdValues());
  parent_a_ = {matrix_a};
  parent_b_ = {matrix_b};
  assert(matrix_a->GetLambdaMatrices()[0].size2() == matrix_b->GetLambdaMatrices()[0].size1());
  
  size_t u = matrix_a->GetLambdaMatrices()[0].size1();
  size_t v = matrix_b->GetLambdaMatrices()[0].size2();
  size_t number_of_simd_values = matrix_a->GetNumberOfSimdValues();

  auto w = GetRegister().template EmplaceWire<auxiliator::MatrixWire<T>>(backend_, u, v, number_of_simd_values);
  output_wires_ = {std::move(w)};

  std::size_t my_id = GetCommunicationLayer().GetMyId();
  auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
  //P0 never receives anything
  if (my_id == 1) {
    matrix_multiply_future_online_ = message_manager.RegisterReceive(
        2, communication::MessageType::kAuxiliatorOnlineMultiplyGate, gate_id_);
  } else if (my_id == 2) {
    matrix_multiply_future_setup_ = message_manager.RegisterReceive(
        0, communication::MessageType::kAuxiliatorSetupMultiplyGate, gate_id_);
    matrix_multiply_future_online_ = message_manager.RegisterReceive(
        1, communication::MessageType::kAuxiliatorOnlineMultiplyGate, gate_id_);
  }
}

template<typename T>
void MatrixMultiplicationGate<T>::EvaluateSetup() {
  using boost::numeric::ublas::matrix;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(parent_a_[0]);
  assert(matrix_a_wire);
  auto matrix_b_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(parent_b_[0]);
  assert(matrix_b_wire);
  
  auto& a_lambda_matrices = matrix_a_wire->GetMutableLambdaMatrices();
  auto& b_lambda_matrices = matrix_b_wire->GetMutableLambdaMatrices();
  auto& a_value_matrices = matrix_a_wire->GetMutableValueMatrices();
  auto& b_value_matrices = matrix_b_wire->GetMutableValueMatrices();
  auto& out_lambda_matrices = matrix_out_wire->GetMutableLambdaMatrices();
  auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
  
  size_t const u = out_lambda_matrices[0].size1();
  size_t const v = out_lambda_matrices[0].size2();
  size_t const number_of_simd_values = matrix_a_wire->GetNumberOfSimdValues();
  
  switch (my_id) {
    case 0: {
      //RNG shared with party 1
      auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
      //RNG shared with party 2
      auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
      std::vector<matrix<UInt128>> gamma_ab2
        = CreateMatrices<UInt128>(u, v, number_of_simd_values);
      //Generate and store gamma_ab1, lambda_z1 into gamma_ab2, out_value_matrices
      SetToRandom(gamma_ab2, out_value_matrices, rng1, gate_id_);
      SetToRandom(out_lambda_matrices, rng2, gate_id_);
      matrix_out_wire->SetSetupIsReady();
      
      matrix_a_wire->GetSetupReadyCondition()->Wait();
      matrix_b_wire->GetSetupReadyCondition()->Wait();
      std::vector<matrix<UInt128>> lambda_as 
        = Convert128(a_lambda_matrices, a_value_matrices);
      std::vector<matrix<UInt128>> lambda_bs 
        = Convert128(b_lambda_matrices, b_value_matrices);

      for (size_t s = 0; s != number_of_simd_values; ++s) {
        auto& lambda_a = lambda_as[s];
        auto& lambda_b = lambda_bs[s];
        auto gamma_ab = prod(lambda_a, lambda_b);
        triple_.AppendTriple(lambda_a, lambda_b, gamma_ab);
        gamma_ab2[s] = gamma_ab - gamma_ab2[s];
      }
      backend_.GetAuxiliatorVerifier()->SetReady();

      auto payload = SerializeMatrices(gamma_ab2);
      auto message = communication::BuildMessage(
                       communication::MessageType::kAuxiliatorSetupMultiplyGate,
                       gate_id_, payload);
      communication_layer.SendMessage(2, message.Release());
      break;
    }
    case 1: {
      //RNG shared with party 0
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      std::vector<matrix<UInt128>> gamma_ab1_extended 
        = CreateMatrices<UInt128>(u, v, number_of_simd_values);
      SetToRandom(gamma_ab1_extended, out_lambda_matrices, rng0, gate_id_);
      matrix_out_wire->SetSetupIsReady();
      
      matrix_a_wire->GetSetupReadyCondition()->Wait();
      matrix_b_wire->GetSetupReadyCondition()->Wait();
      std::vector<matrix<UInt128>> lambda_as 
        = Convert128(a_lambda_matrices);
      std::vector<matrix<UInt128>> lambda_bs 
        = Convert128(b_lambda_matrices);
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        triple_.AppendTriple(
          lambda_as[s], lambda_bs[s], gamma_ab1_extended[s]);
      }
      backend_.GetAuxiliatorVerifier()->SetReady();
      
      //We store gamma_ab1 in out_value_matrices
      ConvertBack(out_value_matrices, gamma_ab1_extended);
      break;
    }
    case 2: {
      //RNG shared with party 0
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      //Generate and store lambda_z2 into out_lambda_matrices
      SetToRandom(out_lambda_matrices, rng0, gate_id_);
      matrix_out_wire->SetSetupIsReady();
      
      matrix_a_wire->GetSetupReadyCondition()->Wait();
      matrix_b_wire->GetSetupReadyCondition()->Wait();
      std::vector<matrix<UInt128>> lambda_as
        = Convert128(a_lambda_matrices);
      std::vector<matrix<UInt128>> lambda_bs
        = Convert128(b_lambda_matrices);
      std::vector<matrix<UInt128>> gamma_ab2_extended
        = CreateMatrices<UInt128>(u, v, number_of_simd_values);
      const auto message = matrix_multiply_future_setup_.get();
      const auto payload = communication::GetMessage(message.data())->payload();
      DeserializeMatrices(gamma_ab2_extended, {payload->Data(), payload->size()});
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        triple_.AppendTriple(
          lambda_as[s], lambda_bs[s], gamma_ab2_extended[s]);
      }
      backend_.GetAuxiliatorVerifier()->SetReady();
      //We store gamma_ab2 in out_value_matrices
      ConvertBack(out_value_matrices, gamma_ab2_extended);
      break;
    }
  }
}

template<typename T>
void MatrixMultiplicationGate<T>::EvaluateOnline() {
  using boost::numeric::ublas::noalias;
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto matrix_out_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
  assert(matrix_out_wire);
  auto matrix_a_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(parent_a_[0]);
  assert(matrix_a_wire);
  auto matrix_b_wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(parent_b_[0]);
  assert(matrix_b_wire);
  
  auto& a_lambda_matrices = matrix_a_wire->GetMutableLambdaMatrices();
  auto& a_value_matrices = matrix_a_wire->GetMutableValueMatrices();
  auto& b_lambda_matrices = matrix_b_wire->GetMutableLambdaMatrices();
  auto& b_value_matrices = matrix_b_wire->GetMutableValueMatrices();
  auto& out_lambda_matrices = matrix_out_wire->GetMutableLambdaMatrices();
  auto& out_value_matrices = matrix_out_wire->GetMutableValueMatrices();
  
  size_t const u = out_lambda_matrices[0].size1();
  size_t const v = out_lambda_matrices[0].size2();
  size_t const number_of_simd_values = matrix_a_wire->GetNumberOfSimdValues();
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();

  if (my_id != 0) {
    if(my_id == 1) {
      for (size_t s = 0; s != number_of_simd_values; ++s) {
        //out_value_matrices contains gamma_ab1
        noalias(out_value_matrices[s]) +=
          prod(a_value_matrices[s], b_value_matrices[s])
          + prod(a_value_matrices[s], b_lambda_matrices[s])
          + prod(a_lambda_matrices[s], b_value_matrices[s]);
        Truncate(out_value_matrices[s], precision_);
        noalias(out_value_matrices[s]) -= out_lambda_matrices[s];
      }
    } else if(my_id == 2) {
      for (size_t s = 0; s != number_of_simd_values; ++s) {
        //out_value_matrices contains gamma_ab2
        noalias(out_value_matrices[s]) += 
          prod(a_value_matrices[s], b_lambda_matrices[s])
          + prod(a_lambda_matrices[s], b_value_matrices[s]);
        Truncate(out_value_matrices[s], precision_);
        noalias(out_value_matrices[s]) -= out_lambda_matrices[s];
      }
    } else {
      assert(false);
    }

    {
      auto payload = SerializeMatrices(out_value_matrices);
      auto message = communication::BuildMessage(
          communication::MessageType::kAuxiliatorOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage( (my_id == 1 ? 2 : 1), message.Release());
    }
        
    auto other_party_matrices = CreateMatrices<T>(u, v, number_of_simd_values);
    {
      const auto message = matrix_multiply_future_online_.get();
      const auto payload = communication::GetMessage(message.data())->payload();
      DeserializeMatrices(other_party_matrices, {payload->Data(), payload->size()});
    }
  
    for(size_t s = 0; s != number_of_simd_values; ++s) {
      noalias(out_value_matrices[s]) += other_party_matrices[s];
    }
  }
}

template <typename T>
auxiliator::SharePointer<T> MatrixMultiplicationGate<T>::GetOutputAsAuxiliatorShare() {
  auto wire = std::dynamic_pointer_cast<auxiliator::MatrixWire<T>>(output_wires_[0]);
  assert(wire);
  return std::make_shared<auxiliator::Share<T>>(wire);
}

template class MatrixMultiplicationGate<std::uint8_t>;
template class MatrixMultiplicationGate<std::uint16_t>;
template class MatrixMultiplicationGate<std::uint32_t>;
template class MatrixMultiplicationGate<std::uint64_t>;

}  // namespace fixed_point

}  // namespace encrypto::motion::proto::auxiliator
