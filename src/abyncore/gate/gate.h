#ifndef GATE_H
#define GATE_H

#include <atomic>
#include <iostream>
#include <unordered_set>
#include <vector>

#include "abynparty/core.h"
#include "share/share.h"

#include "utility/constants.h"
#include "utility/helpers.h"
#include "utility/typedefs.h"

#include "communication/output_message.h"

namespace ABYN::Gates {
namespace Interfaces {

//
//  inputs are not defined in the Gate class but only in the child classes
//
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one abstract output
//

class Gate : public std::enable_shared_from_this<Gate> {
 public:
  virtual ~Gate() {
    std::scoped_lock lock(mutex_);
    core_->UnregisterGate(gate_id_);
  };

  virtual void Evaluate() = 0;

  const std::vector<ABYN::Wires::WirePtr> &GetOutputWires() const {
    return output_wires_;
  }

  const std::shared_ptr<Gate> GetShared() { return shared_from_this(); }

  void RegisterWaitingFor(std::size_t wire_id) {
    std::scoped_lock lock(mutex_);
    wire_dependencies_.insert(wire_id);
  }

  void UnregisterWaitingFor(std::size_t wire_id) {
    std::scoped_lock lock(mutex_);
    if (wire_dependencies_.size() > 0 &&
        wire_dependencies_.find(wire_id) != wire_dependencies_.end()) {
      wire_dependencies_.erase(wire_id);
    }
    IfReadyAddToProcessingQueue();
  }

  bool DependenciesAreReady() { return wire_dependencies_.size() == 0; }

  void SetSetupIsReady() { setup_is_ready_ = true; }

  void SetOnlineIsReady() {
    online_is_ready_ = true;
    for (auto &wire : output_wires_) {
      assert(wire);
      wire->SetOnlineFinished();
    }
  }

  bool &SetupIsReady() { return setup_is_ready_; }

  Gate(Gate &) = delete;

 protected:
  std::vector<ABYN::Wires::WirePtr> output_wires_;
  ABYN::CorePtr core_;
  std::int64_t gate_id_ = -1;
  std::unordered_set<std::size_t> wire_dependencies_;

  GateType gate_type_ = InvalidGate;
  bool setup_is_ready_ = false;
  bool online_is_ready_ = false;
  bool requires_online_interaction_ = false;

  bool added_to_active_queue = false;

  Gate() = default;

 private:
  void IfReadyAddToProcessingQueue() {
    if (DependenciesAreReady() && !added_to_active_queue) {
      core_->AddToActiveQueue(gate_id_);
      added_to_active_queue = true;
    }
  }

  std::mutex mutex_;
};

using GatePtr = std::shared_ptr<Gate>;

//
//     | <- one abstract input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one abstract output
//

class OneGate : public Gate {
 public:
  ~OneGate() override = default;

  void Evaluate() override = 0;

  OneGate(OneGate &) = delete;

 protected:
  std::vector<ABYN::Wires::WirePtr> parent_;

  OneGate() = default;
};

//
//     | <- one abstract (perhaps !SharePointer) input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

class InputGate : public OneGate {
 public:
 protected:
  ~InputGate() override = default;

  InputGate() { gate_type_ = GateType::InputGate; }

  InputGate(InputGate &) = delete;

  std::int64_t input_owner_ = -1;
};

using InputGatePtr = std::shared_ptr<InputGate>;

//
//     | <- one SharePtr input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- abstract output
//

class OutputGate : public OneGate {
 public:
  ~OutputGate() override = default;

  OutputGate(OutputGate &) = delete;

  OutputGate() { gate_type_ = GateType::InputGate; }

 protected:
  std::int64_t output_owner_ = -1;
};

using OutputGatePtr = std::shared_ptr<OutputGate>;

//
//   |    | <- two SharePtrs input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

class TwoGate : public Gate {
 protected:
  std::vector<ABYN::Wires::WirePtr> parent_a_;
  std::vector<ABYN::Wires::WirePtr> parent_b_;

  TwoGate() = default;

 public:
  ~TwoGate() override = default;

  void Evaluate() override = 0;
};

//
//  | |... |  <- n SharePointers input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

class nInputGate : public Gate {
 protected:
  std::vector<ABYN::Wires::WirePtr> parents_;

  nInputGate() = default;

 public:
  ~nInputGate() override = default;
};

}  // namespace Interfaces

namespace Arithmetic {

//
//     | <- one unsigned integer input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one SharePointer(new ArithmeticShare) output
//

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticInputGate : public ABYN::Gates::Interfaces::InputGate {
 public:
  ArithmeticInputGate(const std::vector<T> &input, std::size_t input_owner,
                      const ABYN::CorePtr &core)
      : input_(input) {
    input_owner_ = input_owner;
    core_ = core;
    InitializationHelper();
  }

  ArithmeticInputGate(std::vector<T> &&input, std::size_t input_owner,
                      const ABYN::CorePtr &core)
      : input_(std::move(input)) {
    input_owner_ = input_owner;
    core_ = core;
    InitializationHelper();
  }

  void InitializationHelper() {
    static_assert(!std::is_same_v<T, bool>);
    gate_id_ = core_->NextGateId();
    core_->RegisterNextGate(static_cast<Gate *>(this));
    arithmetic_sharing_id_ = core_->NextArithmeticSharingId(input_.size());
    core_->GetLogger()->LogTrace(fmt::format(
        "Created an ArithmeticInputGate with global id {}", gate_id_));
    output_wires_ = {std::static_pointer_cast<ABYN::Wires::Wire>(
        std::make_shared<ABYN::Wires::ArithmeticWire<T>>(input_, core_))};
    auto gate_info = fmt::format("uint{}_t type, gate id {}, owner {}",
                                 sizeof(T) * 8, gate_id_, input_owner_);
    core_->GetLogger()->LogDebug(fmt::format(
        "Allocate an ArithmeticInputGate with following properties: {}",
        gate_info));
  }

  ~ArithmeticInputGate() final = default;

  // non-interactive input sharing based on distributed in advance randomness
  // seeds
  void Evaluate() final {
    auto my_id = core_->GetConfig()->GetMyId();
    std::vector<T> result;
    if (static_cast<std::size_t>(input_owner_) == my_id) {
      result.resize(input_.size());
      SetSetupIsReady();  // we always generate the seed for input sharing
                          // before we start evaluating the circuit

      auto log_string = std::string("");
      for (auto i = 0u; i < core_->GetConfig()->GetNumOfParties(); ++i) {
        if (i == my_id) {
          continue;
        }
        auto randomness =
            std::move(core_->GetConfig()
                          ->GetCommunicationContext(i)
                          ->GetMyRandomnessGenerator()
                          ->template GetUnsigned<T>(arithmetic_sharing_id_,
                                                    input_.size()));
        log_string.append(fmt::format("id#{}:{} ", i, randomness.at(0)));
        for (auto j = 0u; j < result.size(); ++j) {
          result.at(j) += randomness.at(j);
        }
      }
      for (auto j = 0u; j < result.size(); ++j) {
        result.at(j) = input_.at(j) - result.at(j);
      }

      auto s = fmt::format(
          "My (id#{}) arithmetic input sharing for gate#{}, my input: {}, my "
          "share: {}, expected shares of other parties: {}",
          input_owner_, gate_id_, input_.at(0), result.at(0), log_string);
      core_->GetLogger()->LogTrace(s);
    } else {
      auto &rand_generator =
          core_->GetConfig()
              ->GetCommunicationContext(static_cast<std::size_t>(input_owner_))
              ->GetTheirRandomnessGenerator();
      Helpers::WaitFor(rand_generator->IsInitialized());
      SetSetupIsReady();

      result = std::move(rand_generator->template GetUnsigned<T>(
          arithmetic_sharing_id_, input_.size()));

      auto s = fmt::format(
          "Arithmetic input sharing (gate#{}) of Party's#{} input, got a share "
          "{} from the seed",
          gate_id_, input_owner_, result.at(0));
      core_->GetLogger()->LogTrace(s);
    }
    auto my_wire = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
        output_wires_.at(0));
    assert(my_wire);
    my_wire->GetMutableValuesOnWire() = std::move(result);
    SetOnlineIsReady();
    core_->IncrementEvaluatedGatesCounter();
    core_->GetLogger()->LogTrace(
        fmt::format("Evaluated ArithmeticInputGate with id#{}", gate_id_));
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  ABYN::Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = GetOutputArithmeticWire();
    auto result =
        std::make_shared<ABYN::Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  ABYN::Wires::ArithmeticWirePtr<T> GetOutputArithmeticWire() {
    auto result = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
        output_wires_.at(0));
    assert(result);
    return result;
  }

 private:
  std::size_t arithmetic_sharing_id_;

  std::vector<T> input_;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticOutputGate : public ABYN::Gates::Interfaces::OutputGate {
 protected:
  std::vector<T> output_;
  std::vector<std::vector<T>> shared_outputs_;

  // indicates whether this party obtains the output
  bool is_my_output_ = false;

  const bool &parent_finished_;

  std::mutex m;

 public:
  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  ABYN::Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire =
        std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
            output_wires_.at(0));
    assert(arithmetic_wire);
    auto result =
        std::make_shared<ABYN::Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  ArithmeticOutputGate(const ABYN::Wires::ArithmeticWirePtr<T> &parent,
                       std::size_t output_owner)
      : parent_finished_(parent->IsReady()) {
    if (parent->GetProtocol() != Protocol::ArithmeticGMW) {
      auto sharing_type = Helpers::Print::ToString(parent->GetProtocol());
      throw(std::runtime_error(
          (fmt::format("Arithmetic output gate expects an arithmetic share, "
                       "got a share of type {}",
                       sharing_type))));
    }

    parent_ = {parent};
    output_owner_ = output_owner;
    output_.resize(parent->GetNumOfParallelValues());
    requires_online_interaction_ = true;
    gate_type_ = GateType::InteractiveGate;

    core_ = parent->GetCore();
    gate_id_ = core_->NextGateId();
    core_->RegisterNextGate(static_cast<Gate *>(this));

    RegisterWaitingFor(parent_.at(0)->GetWireId());
    parent_.at(0)->RegisterWaitingGate(gate_id_);

    if (core_->GetConfig()->GetMyId() ==
        static_cast<std::size_t>(output_owner_)) {
      is_my_output_ = true;
    }

    output_wires_ = {std::static_pointer_cast<ABYN::Wires::Wire>(
        std::make_shared<ABYN::Wires::ArithmeticWire<T>>(output_, core_))};

    auto gate_info = fmt::format("uint{}_t type, gate id {}, owner {}",
                                 sizeof(T) * 8, gate_id_, output_owner_);
    core_->GetLogger()->LogTrace(fmt::format(
        "Allocate an ArithmeticOutputGate with following properties: {}",
        gate_info));
  }

  ArithmeticOutputGate(const ABYN::Shares::ArithmeticSharePtr<T> &parent,
                       std::size_t output_owner)
      : ArithmeticOutputGate(parent->GetArithmeticWire(), output_owner) {}

  ~ArithmeticOutputGate() final = default;

  void Evaluate() final {
    auto arithmetic_wire =
        std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
            parent_.at(0));
    assert(arithmetic_wire);
    output_ = arithmetic_wire->GetValuesOnWire();

    if (is_my_output_) {
      // wait until all conditions are fulfilled
      Helpers::WaitFor(parent_finished_);
      auto &config = core_->GetConfig();
      shared_outputs_.resize(core_->GetConfig()->GetNumOfParties());

      for (auto i = 0u; i < config->GetNumOfParties(); ++i) {
        if (i == config->GetMyId()) {
          continue;
        }
        bool success = false;
        auto &data_storage =
            config->GetCommunicationContext(i)->GetDataStorage();
        assert(shared_outputs_.at(i).size() == 0);
        while (!success) {
          auto message = data_storage.GetOutputMessage(gate_id_);
          if (message != nullptr) {
            shared_outputs_.at(i) = std::move(Helpers::FromByteVector<T>(
                *message->wires()->Get(0)->payload()));
            success = true;
          }
          if (!success) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
          };
        }
      }

      shared_outputs_.at(config->GetMyId()) = output_;
      output_ = std::move(Helpers::AddVectors(shared_outputs_));

      std::string shares{""};
      for (auto i = 0u; i < config->GetNumOfParties(); ++i) {
        shares.append(fmt::format(
            "id#{}:{} ", i, Helpers::Print::ToString(shared_outputs_.at(i))));
      }

      auto result = std::move(Helpers::Print::ToString(output_));

      core_->GetLogger()->LogTrace(
          fmt::format("Received output shares: {} from other parties, "
                      "reconstructed result is {}",
                      shares, result));

      auto arithmetic_output_wire =
          std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
              output_wires_.at(0));
      assert(arithmetic_output_wire);
      arithmetic_output_wire->GetMutableValuesOnWire() = output_;
    } else {
      auto payload = Helpers::ToByteVector(output_);
      auto output_message =
          ABYN::Communication::BuildOutputMessage(gate_id_, payload);
      core_->Send(output_owner_, output_message);
    }
    SetOnlineIsReady();
    core_->IncrementEvaluatedGatesCounter();
    core_->GetLogger()->LogTrace(
        fmt::format("Evaluated ArithmeticOutputGate with id#{}", gate_id_));
  }
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticAdditionGate : public ABYN::Gates::Interfaces::TwoGate {
 public:
  ArithmeticAdditionGate(const ABYN::Wires::ArithmeticWirePtr<T> &a,
                         const ABYN::Wires::ArithmeticWirePtr<T> &b)
      : parent_a_finished_(a->IsReady()), parent_b_finished_(b->IsReady()) {
    parent_a_ = {std::static_pointer_cast<ABYN::Wires::Wire>(a)};
    parent_b_ = {std::static_pointer_cast<ABYN::Wires::Wire>(b)};
    core_ = parent_a_.at(0)->GetCore();

    assert(parent_a_.at(0)->GetNumOfParallelValues() ==
           parent_b_.at(0)->GetNumOfParallelValues());
    output_.resize(parent_a_.at(0)->GetNumOfParallelValues());
    requires_online_interaction_ = false;
    gate_type_ = GateType::NonInteractiveGate;

    gate_id_ = core_->NextGateId();
    core_->RegisterNextGate(static_cast<Gate *>(this));

    RegisterWaitingFor(parent_a_.at(0)->GetWireId());
    parent_a_.at(0)->RegisterWaitingGate(gate_id_);

    RegisterWaitingFor(parent_b_.at(0)->GetWireId());
    parent_b_.at(0)->RegisterWaitingGate(gate_id_);

    output_wires_ = {std::move(std::static_pointer_cast<ABYN::Wires::Wire>(
        std::make_shared<ABYN::Wires::ArithmeticWire<T>>(output_, core_)))};

    auto gate_info = fmt::format(
        "uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
        parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    core_->GetLogger()->LogTrace(fmt::format(
        "Allocate an ArithmeticAdditionGate with following properties: {}",
        gate_info));

    SetSetupIsReady();
  }

  ~ArithmeticAdditionGate() final = default;

  void Evaluate() final {
    Helpers::WaitFor(parent_a_finished_);
    Helpers::WaitFor(parent_b_finished_);

    auto wire_a = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
        parent_a_.at(0));
    auto wire_b = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
        parent_b_.at(0));

    assert(wire_a);
    assert(wire_b);

    output_ = Helpers::AddVectors(wire_a->GetValuesOnWire(),
                                  wire_b->GetValuesOnWire());

    auto arithmetic_wire =
        std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
            output_wires_.at(0));
    arithmetic_wire->GetMutableValuesOnWire() = std::move(output_);
    assert(output_.size() == 0);

    SetOnlineIsReady();
    core_->IncrementEvaluatedGatesCounter();
    core_->GetLogger()->LogTrace(
        fmt::format("Evaluated ArithmeticAdditionGate with id#{}", gate_id_));
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  ABYN::Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire =
        std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
            output_wires_.at(0));
    assert(arithmetic_wire);
    auto result =
        std::make_shared<ABYN::Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  ArithmeticAdditionGate() = delete;

  ArithmeticAdditionGate(Gate &) = delete;

 protected:
  const bool &parent_a_finished_;
  const bool &parent_b_finished_;
  std::vector<T> output_;
};

}  // namespace Arithmetic

namespace GMW {

class GMWInputGate : public ABYN::Gates::Interfaces::InputGate {
 public:
  GMWInputGate(const std::vector<u8> &input, std::size_t party_id,
               const ABYN::CorePtr &core, std::size_t bits = 0)
      : input_({input}), bits_(bits), party_id_(party_id) {
    core_ = core;
    InitializationHelper();
  }

  GMWInputGate(std::vector<u8> &&input, std::size_t party_id,
               const ABYN::CorePtr &core, std::size_t bits = 0)
      : input_({std::move(input)}), bits_(bits), party_id_(party_id) {
    core_ = core;
    InitializationHelper();
  }

  GMWInputGate(const std::vector<std::vector<u8>> &input, std::size_t party_id,
               const ABYN::CorePtr &core, std::size_t bits = 0)
      : input_({input}), bits_(bits), party_id_(party_id) {
    core_ = core;
    InitializationHelper();
  }

  GMWInputGate(std::vector<std::vector<u8>> &&input, std::size_t party_id,
               const ABYN::CorePtr &core, std::size_t bits = 0)
      : input_({std::move(input)}), bits_(bits), party_id_(party_id) {
    core_ = core;
    InitializationHelper();
  }

  void InitializationHelper() {
    gate_id_ = core_->NextGateId();
    core_->RegisterNextGate(static_cast<Gate *>(this));

    assert(input_.size() > 0);        // assert >=1 wire
    assert(input_.at(0).size() > 0);  // assert >=1 SIMD bits
    // assert SIMD lengths of all wires are equal
    assert(ABYN::Helpers::Compare::Dimensions(input_));

    if (bits_ == 0) {
      bits_ = input_.at(0).size() * 8;
    }

    auto input_size = input_.at(0).size();
    boolean_sharing_id_ =
        core_->NextBooleanGMWSharingId(input_.size() * input_size * 8);
    core_->GetLogger()->LogTrace(fmt::format(
        "Created an ArithmeticInputGate with global id {}", gate_id_));
    for (auto &v : input_) {
      auto wire = std::make_shared<Wires::GMWWire>(v, core_, bits_);
      output_wires_.push_back(
          std::static_pointer_cast<ABYN::Wires::Wire>(wire));
    }

    auto gate_info = fmt::format("gate id {},", gate_id_);
    core_->GetLogger()->LogDebug(fmt::format(
        "Allocate an ArithmeticInputGate with following properties: {}",
        gate_info));
  }

  ~GMWInputGate() final = default;

  void Evaluate() final {
    auto my_id = core_->GetConfig()->GetMyId();
    // we always generate the seed for input sharing before we start evaluating
    // the circuit
    if (party_id_ == my_id) {
      SetSetupIsReady();
    }

    std::vector<CBitVector> result(input_.size());
    auto sharing_id = boolean_sharing_id_;
    for (auto i = 0ull; i < result.size(); ++i) {
      if (party_id_ == my_id) {
        result.at(i).CreateExact(bits_);
        auto log_string = std::string("");
        for (auto j = 0u; j < core_->GetConfig()->GetNumOfParties(); ++j) {
          if (j == my_id) {
            continue;
          }

          auto &rand_generator = core_->GetConfig()
                                     ->GetCommunicationContext(j)
                                     ->GetMyRandomnessGenerator();
          auto randomness_vector =
              std::move(rand_generator->GetBits(sharing_id, bits_));

          log_string.append(
              fmt::format("id#{}:{} ", j, randomness_vector.at(0)));
          CBitVector randomness;
          randomness.AttachBuf(randomness_vector.data(),
                               randomness_vector.size());
          result.at(i).XOR(&randomness);
          randomness.DetachBuf();
          sharing_id += bits_;
        }
        auto s = fmt::format(
            "My (id#{}) arithmetic input sharing for gate#{}, my input: {}, my "
            "share: {}, expected shares of other parties: {}",
            party_id_, gate_id_, input_.at(0).at(0) ^ result.at(0).GetByte(0),
            input_.at(0).at(0), log_string);
        core_->GetLogger()->LogTrace(s);
      } else {
        auto &rand_generator = core_->GetConfig()
                                   ->GetCommunicationContext(party_id_)
                                   ->GetTheirRandomnessGenerator();
        Helpers::WaitFor(rand_generator->IsInitialized());
        SetSetupIsReady();
        auto randomness_v =
            std::move(rand_generator->GetBits(sharing_id, bits_));
        result.at(i).Copy(randomness_v.data(), 0, randomness_v.size());

        auto s = fmt::format(
            "Arithmetic input sharing (gate#{}) of Party's#{} input, got a "
            "share {} from the seed",
            gate_id_, party_id_, result.at(0).GetByte(0));
        core_->GetLogger()->LogTrace(s);
        sharing_id += bits_;
      }
    }

    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      auto my_wire =
          std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_wires_.at(i));
      assert(my_wire);
      auto buf = result.at(i).GetArr();
      result.at(i).DetachBuf();
      my_wire->GetMutableValuesOnWire().AttachBuf(buf);
    }
    SetOnlineIsReady();
    core_->IncrementEvaluatedGatesCounter();
    core_->GetLogger()->LogTrace(
        fmt::format("Evaluated ArithmeticInputGate with id#{}", gate_id_));
  };

  const ABYN::Shares::GMWSharePtr GetOutputAsGMWShare() {
    auto result = std::make_shared<ABYN::Shares::GMWShare>(output_wires_);
    assert(result);
    return result;
  }

 private:
  std::vector<std::vector<u8>>
      input_;  ///< two-dimensional vector for storing the raw inputs

  std::size_t bits_;  ///< Number of parallel values on wires

  std::size_t party_id_;  ///< Indicates whether which party shares the input

  std::size_t
      boolean_sharing_id_;  ///< Sharing ID for Boolean GMW for generating
                            ///< correlated randomness using AES CTR

  std::vector<CBitVector> output;  ///< CBitVector for storing the raw outputs
};
}  // namespace GMW
}  // namespace ABYN::Gates
#endif  // GATE_H
