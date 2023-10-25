// MIT License
//
// Copyright (c) 2020 Lennart Braun
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

#include "gate_executor.h"

#include "base/register.h"
#include "protocols/gate.h"
#include "statistics/run_time_statistics.h"
#include "utility/fiber_thread_pool/fiber_thread_pool.hpp"
#include "utility/logger.h"
#include "communication/transport.h"
#include "protocols/wire.h"
#include "base/backend.h"
#include "protocols/astra/astra_verifier.h"
#include "protocols/swift/swift_verifier.h"
#include "protocols/swift/swift_truncation.h"

namespace encrypto::motion {

GateExecutor::GateExecutor(Backend& backend, Register& reg, std::function<void(void)> presetup_function,
                           std::shared_ptr<Logger> logger)
    : backend_(backend),
      register_(reg),
      presetup_function_(std::move(presetup_function)),
      logger_(std::move(logger)),
      gate_id_(backend.GetRegister()->NextGateId()) {
  using communication::MessageType::kGateExecutorSynchronizeSetup;
  
  auto& communication_layer = backend_.GetCommunicationLayer();
  auto& message_manager = communication_layer.GetMessageManager();
  uint64_t my_id = communication_layer.GetMyId();
  uint64_t next_id = (my_id + 1) % 3;
  uint64_t previous_id = (my_id + 2) % 3;
  
  executor_future_setup_previous_party_ = 
    message_manager.RegisterReceive(previous_id, kGateExecutorSynchronizeSetup, gate_id_);
  executor_future_setup_next_party_ = 
    message_manager.RegisterReceive(next_id, kGateExecutorSynchronizeSetup, gate_id_);
}

void GateExecutor::EvaluateSetupOnline(RunTimeStatistics& statistics) {
  using namespace std::chrono;
  using communication::MessageType::kGateExecutorSynchronizeSetup;
  statistics.RecordStart<RunTimeStatistics::StatisticsId::kEvaluate>();

  presetup_function_();

  if (logger_) {
    logger_->LogInfo(
        "Start evaluating the circuit gates sequentially (online after all finished setup)");
  }

  // create a pool with std::thread::hardware_concurrency() no. of threads
  // to execute fibers
  FiberThreadPool fiber_pool(0, 2 * register_.GetTotalNumberOfGates());
  auto& communication_layer = backend_.GetCommunicationLayer();

  // ------------------------------ setup phase ------------------------------ 
  statistics.RecordStart<RunTimeStatistics::StatisticsId::kGatesSetup>();
  auto setup_start = steady_clock::now();
  backend_.GetSwiftTruncation()->InitializeRandom();

  // Evaluate the setup phase of all the gates
  fiber_pool.post([&] {
    backend_.GetSwiftTruncation()->GenerateR();
  });
  fiber_pool.post([&] {
    backend_.GetSwiftTruncation()->GenerateRd();
  });
  for (auto& gate : register_.GetGates()) {
    if (gate->NeedsSetup()) {
      fiber_pool.post([&] {
        gate->EvaluateSetup();
        gate->SetSetupIsReady();
        register_.IncrementEvaluatedGatesSetupCounter();
      });
    } else {
      // cannot be done earlier because output wires did not yet exist
      gate->SetSetupIsReady();
    }
  }

  register_.CheckSetupCondition();
  register_.GetGatesSetupDoneCondition()->Wait();
  backend_.GetAstraVerifier()->SetReady();
  backend_.GetSwiftVerifier()->SetReady();
  backend_.GetSociumVerifier()->SetReady();
  backend_.GetSwiftInputHashVerifier()->SetReady();
  backend_.GetSwiftOutputHashVerifier()->SetReady();
  backend_.GetSwiftMultiplyHashVerifier()->SetReady();
  backend_.GetAstraVerifier()->GetIsReadyCondition().Wait();
  backend_.GetSwiftVerifier()->GetIsReadyCondition().Wait();
  backend_.GetSociumVerifier()->GetIsReadyCondition().Wait();
  assert(register_.GetNumberOfEvaluatedGatesSetup() == register_.GetNumberOfGatesSetup());
  communication_layer.WaitForEmptyingSendBuffer();
  assert(communication_layer.IsSendBufferEmpty());
  auto setup_end = steady_clock::now();
  statistics.RecordEnd<RunTimeStatistics::StatisticsId::kGatesSetup>();
  duration<double> setup_diff = setup_end - setup_start;
  std::cout << "CONTROL Setup Evaluation took: " << double(setup_diff.count() * 1'000) << " ms" << std::endl;
  uint64_t my_id = communication_layer.GetMyId();
  size_t bytes_sent_to_s0 = 0;
  size_t bytes_sent_to_s1 = 0;
  size_t bytes_sent_to_s2 = 0;
  switch(my_id) {
    case 0: {
      bytes_sent_to_s1 = communication_layer.GetSendS1Communication();
      bytes_sent_to_s2 = communication_layer.GetSendS2Communication();
      std::cout << "CONTROL Setup bytes sent to S1: " << bytes_sent_to_s1 << std::endl;
      std::cout << "CONTROL Setup bytes sent to S2: " << bytes_sent_to_s2 << std::endl;
      break;
    }
    case 1: {
      bytes_sent_to_s0 = communication_layer.GetSendS0Communication();
      bytes_sent_to_s2 = communication_layer.GetSendS2Communication();
      std::cout << "CONTROL Setup bytes sent to S0: " << bytes_sent_to_s0 << std::endl;
      std::cout << "CONTROL Setup bytes sent to S2: " << bytes_sent_to_s2 << std::endl;
      break;
    }
    case 2: {
      bytes_sent_to_s0 = communication_layer.GetSendS0Communication();
      bytes_sent_to_s1 = communication_layer.GetSendS1Communication();
      std::cout << "CONTROL Setup bytes sent to S0: " << bytes_sent_to_s0 << std::endl;
      std::cout << "CONTROL Setup bytes sent to S1: " << bytes_sent_to_s1 << std::endl;
      break;
    }
  }
  
  g_setup_statistics = statistics;
  communication::g_setup_transport_statistics = backend_.GetCommunicationLayer().GetTransportStatistics();
  
  std::vector<uint8_t> synchronize_message{uint8_t(42)};
  {
    auto message = communication::BuildMessage(kGateExecutorSynchronizeSetup, gate_id_, synchronize_message);
    communication_layer.BroadcastMessage(message.Release());
  }
  executor_future_setup_previous_party_.get();
  executor_future_setup_next_party_.get();
  
  // ------------------------------ online phase ------------------------------
  statistics.RecordStart<RunTimeStatistics::StatisticsId::kGatesOnline>();
  auto online_start = steady_clock::now();

  // Evaluate the online phase of all the gates
  for (auto& gate : register_.GetGates()) {
    if (gate->NeedsOnline()) {
      fiber_pool.post([&] {
        gate->EvaluateOnline();
        gate->SetOnlineIsReady();
        register_.IncrementEvaluatedGatesOnlineCounter();
      });
    } else {
      // cannot be done earlier because output wires did not yet exist
      gate->SetOnlineIsReady();
    }
  }

  register_.CheckOnlineCondition();
  register_.GetGatesOnlineDoneCondition()->Wait();
  backend_.GetSwiftInputHashVerifier()->GetIsReadyCondition().Wait();
  backend_.GetSwiftOutputHashVerifier()->GetIsReadyCondition().Wait();
  backend_.GetSwiftMultiplyHashVerifier()->GetIsReadyCondition().Wait();
  assert(register_.GetNumberOfGatesOnline() == register_.GetNumberOfGatesOnline());

  auto online_end = steady_clock::now();
  statistics.RecordEnd<RunTimeStatistics::StatisticsId::kGatesOnline>();

  // --------------------------------------------------------------------------

  fiber_pool.join();

  statistics.RecordEnd<RunTimeStatistics::StatisticsId::kEvaluate>();
  
  duration<double> online_diff = online_end - online_start;
  std::cout << "CONTROL Online Evaluation took: " << double(online_diff.count() * 1'000) << " ms" << std::endl;
  switch(my_id) {
    case 0: {
      bytes_sent_to_s1 = communication_layer.GetSendS1Communication() - bytes_sent_to_s1;
      bytes_sent_to_s2 = communication_layer.GetSendS2Communication() - bytes_sent_to_s2;
      std::cout << "CONTROL Online bytes sent to S1: " << bytes_sent_to_s1 << std::endl;
      std::cout << "CONTROL Online bytes sent to S2: " << bytes_sent_to_s2 << std::endl;
      break;
    }
    case 1: {
      bytes_sent_to_s0 = communication_layer.GetSendS0Communication() - bytes_sent_to_s0;
      bytes_sent_to_s2 = communication_layer.GetSendS2Communication() - bytes_sent_to_s2;
      std::cout << "CONTROL Online bytes sent to S0: " << bytes_sent_to_s0 << std::endl;
      std::cout << "CONTROL Online bytes sent to S2: " << bytes_sent_to_s2 << std::endl;
      break;
    }
    case 2: {
      bytes_sent_to_s0 = communication_layer.GetSendS0Communication() - bytes_sent_to_s0;
      bytes_sent_to_s1 = communication_layer.GetSendS1Communication() - bytes_sent_to_s1;
      std::cout << "CONTROL Online bytes sent to S0: " << bytes_sent_to_s0 << std::endl;
      std::cout << "CONTROL Online bytes sent to S1: " << bytes_sent_to_s1 << std::endl;
      break;
    }
  }
}

void GateExecutor::Evaluate(RunTimeStatistics& statistics) {
  logger_->LogInfo(
      "Start evaluating the circuit gates in parallel (online as soon as some finished setup)");

  statistics.RecordStart<RunTimeStatistics::StatisticsId::kEvaluate>();

  // Run preprocessing setup in a separate thread
  auto preprocessing_future = std::async(std::launch::async, [this] { presetup_function_(); });

  // create a pool with std::thread::hardware_concurrency() no. of threads
  // to execute fibers
  FiberThreadPool fiber_pool(0, register_.GetTotalNumberOfGates());

  // Evaluate all the gates
  for (auto& gate : register_.GetGates()) {
    if (gate->NeedsSetup() || gate->NeedsOnline()) {
      fiber_pool.post([&] {
        gate->EvaluateSetup();
        gate->SetSetupIsReady();
        if (gate->NeedsSetup()) {
          register_.IncrementEvaluatedGatesSetupCounter();
        }

        // XXX: maybe insert a 'yield' here?
        gate->EvaluateOnline();
        gate->SetOnlineIsReady();
        if (gate->NeedsOnline()) {
          register_.IncrementEvaluatedGatesOnlineCounter();
        }
      });
    } else {
      // cannot be done earlier because output wires did not yet exist
      gate->SetSetupIsReady();
      gate->SetOnlineIsReady();
    }
  }

  preprocessing_future.get();

  // we have to wait until all gates are evaluated before we close the pool
  register_.CheckOnlineCondition();
  register_.GetGatesOnlineDoneCondition()->Wait();
  fiber_pool.join();

  statistics.RecordEnd<RunTimeStatistics::StatisticsId::kEvaluate>();
}

}  // namespace encrypto::motion
