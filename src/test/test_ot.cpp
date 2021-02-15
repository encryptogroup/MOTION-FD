// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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

#include "gtest/gtest.h"

#include "test_constants.h"

#include "base/backend.h"
#include "base/motion_base_provider.h"
#include "base/party.h"
#include "data_storage/base_ot_data.h"
#include "oblivious_transfer/ot_provider.h"

namespace {

constexpr auto kNumberOfPartiesList = {2u, 3u};

template <typename T>
using vvv = std::vector<std::vector<std::vector<T>>>;

TEST(ObliviousTransfer, Random1oo2OtsFromOtExtension) {
  constexpr std::size_t kNumberOfOts{10};
  for (auto number_of_parties : kNumberOfPartiesList) {
    try {
      std::mt19937_64 random(0);
      std::uniform_int_distribution<std::size_t> distribution_bitlength(1, 1000);
      std::uniform_int_distribution<std::size_t> distribution_batch_size(1, 10);
      std::array<std::size_t, kNumberOfOts> bitlength, ots_in_batch;
      for (auto i = 0ull; i < bitlength.size(); ++i) {
        bitlength.at(i) = distribution_bitlength(random);
        ots_in_batch.at(i) = distribution_batch_size(random);
      }

      bitlength.at(bitlength.size() - 1) = 1;

      std::vector<encrypto::motion::PartyPointer> motion_parties(
          std::move(encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
      for (auto& party : motion_parties) {
        party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      }
      std::vector<std::thread> threads(number_of_parties);

      // my id, other id, data
      vvv<std::shared_ptr<encrypto::motion::OtVectorSender>> sender_ot(number_of_parties);
      vvv<std::shared_ptr<encrypto::motion::OtVectorReceiver>> receiver_ot(number_of_parties);
      vvv<std::vector<encrypto::motion::BitVector<>>> sender_messages(number_of_parties),
          receiver_messages(number_of_parties);
      vvv<encrypto::motion::BitVector<>> choices(number_of_parties);

      for (auto i = 0ull; i < number_of_parties; ++i) {
        sender_ot.at(i).resize(number_of_parties);
        receiver_ot.at(i).resize(number_of_parties);
        sender_messages.at(i).resize(number_of_parties);
        receiver_messages.at(i).resize(number_of_parties);
        choices.at(i).resize(number_of_parties);
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        threads.at(i) = std::thread([&bitlength, &ots_in_batch, &sender_ot, &receiver_ot,
                                     &motion_parties, i, number_of_parties]() {
          motion_parties.at(i)->GetBackend()->GetBaseProvider().Setup();
          for (auto j = 0u; j < motion_parties.size(); ++j) {
            if (i != j) {
              auto& ot_provider = motion_parties.at(i)->GetBackend()->GetOtProvider(j);
              for (auto k = 0ull; k < kNumberOfOts; ++k) {
                sender_ot.at(i).at(j).push_back(ot_provider.RegisterSend(
                    bitlength.at(k), ots_in_batch.at(k), encrypto::motion::OtProtocol::kROt));
                receiver_ot.at(i).at(j).push_back(ot_provider.RegisterReceive(
                    bitlength.at(k), ots_in_batch.at(k), encrypto::motion::OtProtocol::kROt));
              }
            }
          }
          motion_parties.at(i)->GetBackend()->OtExtensionSetup();
          motion_parties.at(i)->Finish();
        });
      }

      for (auto& t : threads) {
        t.join();
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        for (auto j = 0u; j < motion_parties.size(); ++j) {
          if (i != j) {
            for (auto k = 0ull; k < kNumberOfOts; ++k) {
              sender_messages.at(i).at(j).push_back(sender_ot.at(i).at(j).at(k)->GetOutputs());
              choices.at(j).at(i).push_back(receiver_ot.at(j).at(i).at(k)->GetChoices());
              receiver_messages.at(j).at(i).push_back(receiver_ot.at(j).at(i).at(k)->GetOutputs());

              for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
                if (!choices.at(j).at(i).at(k)[l]) {
                  ASSERT_EQ(receiver_messages.at(j).at(i).at(k).at(l),
                            sender_messages.at(i).at(j).at(k).at(l).Subset(0, bitlength.at(k)));
                } else {
                  ASSERT_EQ(receiver_messages.at(j).at(i).at(k).at(l),
                            sender_messages.at(i).at(j).at(k).at(l).Subset(bitlength.at(k),
                                                                           2 * bitlength.at(k)));
                }
              }
            }
          }
        }
      }
    } catch (std::exception& e) {
      std::cerr << e.what() << std::endl;
    }
  }
}

TEST(ObliviousTransfer, General1oo2OtsFromOtExtension) {
  constexpr std::size_t kNumberOfOts{10};
  for (auto number_of_parties : kNumberOfPartiesList) {
    try {
      std::mt19937_64 random(0);
      std::uniform_int_distribution<std::size_t> distribution_bitlength(1, 1000);
      std::uniform_int_distribution<std::size_t> distribution_batch_size(1, 10);
      std::array<std::size_t, kNumberOfOts> bitlength, ots_in_batch;
      for (auto i = 0ull; i < bitlength.size(); ++i) {
        bitlength.at(i) = distribution_bitlength(random);
        ots_in_batch.at(i) = distribution_batch_size(random);
      }

      bitlength.at(bitlength.size() - 1) = 1;

      std::vector<encrypto::motion::PartyPointer> motion_parties(
          std::move(encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
      for (auto& party : motion_parties) {
        party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      }
      std::vector<std::thread> threads(number_of_parties);

      // my id, other id, data
      vvv<std::shared_ptr<encrypto::motion::OtVectorSender>> sender_ot(number_of_parties);
      vvv<std::shared_ptr<encrypto::motion::OtVectorReceiver>> receiver_ot(number_of_parties);
      vvv<std::vector<encrypto::motion::BitVector<>>> sender_messages(number_of_parties),
          receiver_messages(number_of_parties);
      vvv<encrypto::motion::BitVector<>> choices(number_of_parties);

      for (auto i = 0ull; i < number_of_parties; ++i) {
        sender_ot.at(i).resize(number_of_parties);
        receiver_ot.at(i).resize(number_of_parties);
        sender_messages.at(i).resize(number_of_parties);
        receiver_messages.at(i).resize(number_of_parties);
        choices.at(i).resize(number_of_parties);
      }

      for (auto i = 0ull; i < number_of_parties; ++i) {
        for (auto j = 0ull; j < number_of_parties; ++j) {
          if (i != j) {
            for (auto k = 0ull; k < kNumberOfOts; ++k) {
              sender_messages.at(i).at(j).resize(kNumberOfOts);
              receiver_messages.at(i).at(j).resize(kNumberOfOts);
              choices.at(i).at(j).resize(kNumberOfOts);
              for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
                sender_messages.at(i).at(j).at(k).push_back(
                    encrypto::motion::BitVector<>::SecureRandom(bitlength.at(k) * 2));
              }
              choices.at(i).at(j).at(k) =
                  encrypto::motion::BitVector<>::SecureRandom(ots_in_batch.at(k));
            }
          }
        }
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        threads.at(i) =
            std::thread([&sender_messages, &receiver_messages, &choices, &bitlength, &ots_in_batch,
                         &sender_ot, &receiver_ot, &motion_parties, i, number_of_parties]() {
              motion_parties.at(i)->GetBackend()->GetBaseProvider().Setup();
              for (auto j = 0u; j < motion_parties.size(); ++j) {
                if (i != j) {
                  auto& ot_provider = motion_parties.at(i)->GetBackend()->GetOtProvider(j);
                  for (auto k = 0ull; k < kNumberOfOts; ++k) {
                    sender_ot.at(i).at(j).push_back(
                        ot_provider.RegisterSend(bitlength.at(k), ots_in_batch.at(k)));
                    receiver_ot.at(i).at(j).push_back(
                        ot_provider.RegisterReceive(bitlength.at(k), ots_in_batch.at(k)));
                  }
                }
              }
              motion_parties.at(i)->GetBackend()->OtExtensionSetup();

              for (auto j = 0u; j < motion_parties.size(); ++j) {
                if (i != j) {
                  for (auto k = 0ull; k < kNumberOfOts; ++k) {
                    receiver_ot.at(i).at(j).at(k)->SetChoices(choices.at(i).at(j).at(k));
                    receiver_ot.at(i).at(j).at(k)->SendCorrections();
                    sender_ot.at(i).at(j).at(k)->SetInputs(sender_messages.at(i).at(j).at(k));
                    sender_ot.at(i).at(j).at(k)->SendMessages();
                  }
                }
              }
              motion_parties.at(i)->Finish();
            });
      }

      for (auto& t : threads) {
        t.join();
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        for (auto j = 0u; j < motion_parties.size(); ++j) {
          if (i != j) {
            for (auto k = 0ull; k < kNumberOfOts; ++k) {
              receiver_messages.at(j).at(i).at(k) = receiver_ot.at(j).at(i).at(k)->GetOutputs();
              for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
                if (!choices.at(j).at(i).at(k)[l]) {
                  ASSERT_EQ(receiver_messages.at(j).at(i).at(k).at(l),
                            sender_messages.at(i).at(j).at(k).at(l).Subset(0, bitlength.at(k)));
                } else {
                  ASSERT_EQ(receiver_messages.at(j).at(i).at(k).at(l),
                            sender_messages.at(i).at(j).at(k).at(l).Subset(bitlength.at(k),
                                                                           2 * bitlength.at(k)));
                }
              }
            }
          }
        }
      }
    } catch (std::exception& e) {
      std::cerr << e.what() << std::endl;
    }
  }
}

TEST(ObliviousTransfer, XorCorrelated1oo2OtsFromOtExtension) {
  constexpr std::size_t kNumberOfOts{10};
  for (auto number_of_parties : kNumberOfPartiesList) {
    try {
      std::mt19937_64 random(0);
      std::uniform_int_distribution<std::size_t> distribution_bitlength(1, 1000);
      std::uniform_int_distribution<std::size_t> distribution_batch_size(1, 10);
      std::array<std::size_t, kNumberOfOts> bitlength, ots_in_batch;
      for (auto i = 0ull; i < bitlength.size(); ++i) {
        bitlength.at(i) = distribution_bitlength(random);
        ots_in_batch.at(i) = distribution_batch_size(random);
      }

      bitlength.at(bitlength.size() - 1) = 1;

      std::vector<encrypto::motion::PartyPointer> motion_parties(
          std::move(encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
      for (auto& party : motion_parties) {
        party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      }
      std::vector<std::thread> threads(number_of_parties);
      // my id, other id, data
      vvv<std::shared_ptr<encrypto::motion::OtVectorSender>> sender_ot(number_of_parties);
      vvv<std::shared_ptr<encrypto::motion::OtVectorReceiver>> receiver_ot(number_of_parties);
      vvv<std::vector<encrypto::motion::BitVector<>>> sender_messages(number_of_parties),
          sender_out(number_of_parties), receiver_messages(number_of_parties);
      vvv<encrypto::motion::BitVector<>> choices(number_of_parties);

      for (auto i = 0ull; i < number_of_parties; ++i) {
        sender_ot.at(i).resize(number_of_parties);
        receiver_ot.at(i).resize(number_of_parties);
        sender_messages.at(i).resize(number_of_parties);
        sender_out.at(i).resize(number_of_parties);
        receiver_messages.at(i).resize(number_of_parties);
        choices.at(i).resize(number_of_parties);
      }

      for (auto i = 0ull; i < number_of_parties; ++i) {
        for (auto j = 0ull; j < number_of_parties; ++j) {
          if (i != j) {
            for (auto k = 0ull; k < kNumberOfOts; ++k) {
              sender_messages.at(i).at(j).resize(kNumberOfOts);
              sender_out.at(i).at(j).resize(kNumberOfOts);
              receiver_messages.at(i).at(j).resize(kNumberOfOts);
              choices.at(i).at(j).resize(kNumberOfOts);
              for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
                sender_messages.at(i).at(j).at(k).push_back(
                    encrypto::motion::BitVector<>::SecureRandom(bitlength.at(k)));
              }
              choices.at(i).at(j).at(k) =
                  encrypto::motion::BitVector<>::SecureRandom(ots_in_batch.at(k));
            }
          }
        }
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        threads.at(i) = std::thread([&sender_messages, &receiver_messages, &choices, &bitlength,
                                     &ots_in_batch, &sender_ot, &sender_out, &receiver_ot,
                                     &motion_parties, i, number_of_parties]() {
          motion_parties.at(i)->GetBackend()->GetBaseProvider().Setup();
          for (auto j = 0u; j < motion_parties.size(); ++j) {
            if (i != j) {
              auto& ot_provider = motion_parties.at(i)->GetBackend()->GetOtProvider(j);
              for (auto k = 0ull; k < kNumberOfOts; ++k) {
                sender_ot.at(i).at(j).push_back(ot_provider.RegisterSend(
                    bitlength.at(k), ots_in_batch.at(k), encrypto::motion::OtProtocol::kXcOt));
                receiver_ot.at(i).at(j).push_back(ot_provider.RegisterReceive(
                    bitlength.at(k), ots_in_batch.at(k), encrypto::motion::OtProtocol::kXcOt));
              }
            }
          }
          motion_parties.at(i)->GetBackend()->OtExtensionSetup();
          for (auto j = 0u; j < motion_parties.size(); ++j) {
            if (i != j) {
              for (auto k = 0ull; k < kNumberOfOts; ++k) {
                receiver_ot.at(i).at(j).at(k)->SetChoices(choices.at(i).at(j).at(k));
                receiver_ot.at(i).at(j).at(k)->SendCorrections();
              }
              for (auto k = 0ull; k < kNumberOfOts; ++k) {
                sender_ot.at(i).at(j).at(k)->SetInputs(sender_messages.at(i).at(j).at(k));
                sender_ot.at(i).at(j).at(k)->SendMessages();
              }
            }
          }
          motion_parties.at(i)->Finish();
        });
      }

      for (auto& t : threads) {
        if (t.joinable()) t.join();
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        for (auto j = 0u; j < motion_parties.size(); ++j) {
          if (i == j) continue;
          for (auto k = 0ull; k < kNumberOfOts; ++k) {
            receiver_messages.at(i).at(j).at(k) = receiver_ot.at(i).at(j).at(k)->GetOutputs();
            sender_out.at(i).at(j).at(k) = sender_ot.at(i).at(j).at(k)->GetOutputs();
          }
        }
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        for (auto j = 0u; j < motion_parties.size(); ++j) {
          if (i != j) {
            for (auto k = 0ull; k < kNumberOfOts; ++k) {
              for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
                if (!choices.at(j).at(i).at(k)[l]) {
                  ASSERT_EQ(receiver_messages.at(j).at(i).at(k).at(l),
                            sender_out.at(i).at(j).at(k).at(l).Subset(0, bitlength.at(k)));
                } else {
                  ASSERT_EQ(receiver_messages.at(j).at(i).at(k).at(l),
                            sender_out.at(i).at(j).at(k).at(l).Subset(bitlength.at(k),
                                                                      2 * bitlength.at(k)));
                  ASSERT_EQ(receiver_messages.at(j).at(i).at(k).at(l) ^
                                sender_out.at(i).at(j).at(k).at(l).Subset(0, bitlength.at(k)),
                            sender_messages.at(i).at(j).at(k).at(l));
                }
              }
            }
          }
        }
      }
    } catch (std::exception& e) {
      std::cerr << e.what() << std::endl;
    }
  }
}

TEST(ObliviousTransfer, AdditivelyCorrelated1oo2OtsFromOtExtension) {
  constexpr std::size_t kNumberOfOts{10};
  constexpr std::array<std::size_t, 5> kBitlengths{8, 16, 32, 64, 128};
  for (auto number_of_parties : kNumberOfPartiesList) {
    try {
      std::mt19937_64 random(0);
      std::uniform_int_distribution<std::size_t> distribution_bitlength(0, kBitlengths.size() - 1);
      std::uniform_int_distribution<std::size_t> distribution_batch_size(1, 10);
      std::array<std::size_t, kNumberOfOts> bitlength, ots_in_batch;
      for (auto i = 0ull; i < bitlength.size(); ++i) {
        bitlength.at(i) = kBitlengths.at(distribution_bitlength(random));
        ots_in_batch.at(i) = distribution_batch_size(random);
      }

      std::vector<encrypto::motion::PartyPointer> motion_parties(
          std::move(encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
      for (auto& party : motion_parties) {
        party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      }
      std::vector<std::thread> threads(number_of_parties);

      // my id, other id, data
      vvv<std::shared_ptr<encrypto::motion::OtVectorSender>> sender_ot(number_of_parties);
      vvv<std::shared_ptr<encrypto::motion::OtVectorReceiver>> receiver_ot(number_of_parties);
      vvv<std::vector<encrypto::motion::BitVector<>>> sender_messages(number_of_parties),
          sender_out(number_of_parties), receiver_messages(number_of_parties);
      vvv<encrypto::motion::BitVector<>> choices(number_of_parties);

      for (auto i{0ull}; i < number_of_parties; ++i) {
        sender_ot.at(i).resize(number_of_parties);
        receiver_ot.at(i).resize(number_of_parties);
        sender_messages.at(i).resize(number_of_parties);
        sender_out.at(i).resize(number_of_parties);
        receiver_messages.at(i).resize(number_of_parties);
        choices.at(i).resize(number_of_parties);
      }

      for (auto i = 0ull; i < number_of_parties; ++i) {
        for (auto j = 0ull; j < number_of_parties; ++j) {
          if (i != j) {
            for (auto k = 0ull; k < kNumberOfOts; ++k) {
              sender_messages.at(i).at(j).resize(kNumberOfOts);
              sender_out.at(i).at(j).resize(kNumberOfOts);
              receiver_messages.at(i).at(j).resize(kNumberOfOts);
              choices.at(i).at(j).resize(kNumberOfOts);
              for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
                sender_messages.at(i).at(j).at(k).push_back(
                    encrypto::motion::BitVector<>::SecureRandom(bitlength.at(k)));
              }
              choices.at(i).at(j).at(k) =
                  encrypto::motion::BitVector<>::SecureRandom(ots_in_batch.at(k));
            }
          }
        }
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        threads.at(i) = std::thread([&sender_messages, &receiver_messages, &choices, &bitlength,
                                     &ots_in_batch, &sender_ot, &sender_out, &receiver_ot,
                                     &motion_parties, i, number_of_parties]() {
          motion_parties.at(i)->GetBackend()->GetBaseProvider().Setup();
          for (auto j = 0u; j < motion_parties.size(); ++j) {
            if (i != j) {
              auto& ot_provider = motion_parties.at(i)->GetBackend()->GetOtProvider(j);
              for (auto k = 0ull; k < kNumberOfOts; ++k) {
                sender_ot.at(i).at(j).push_back(ot_provider.RegisterSend(
                    bitlength.at(k), ots_in_batch.at(k), encrypto::motion::OtProtocol::kAcOt));
                receiver_ot.at(i).at(j).push_back(ot_provider.RegisterReceive(
                    bitlength.at(k), ots_in_batch.at(k), encrypto::motion::OtProtocol::kAcOt));
              }
            }
          }
          motion_parties.at(i)->GetBackend()->OtExtensionSetup();

          for (auto j = 0u; j < motion_parties.size(); ++j) {
            if (i != j) {
              // #pragma omp parallel sections
              {
                // #pragma omp section
                {
                  for (auto k = 0ull; k < kNumberOfOts; ++k) {
                    receiver_ot.at(i).at(j).at(k)->SetChoices(choices.at(i).at(j).at(k));
                    receiver_ot.at(i).at(j).at(k)->SendCorrections();
                  }
                }
                // #pragma omp section
                {
                  for (auto k = 0ull; k < kNumberOfOts; ++k) {
                    sender_ot.at(i).at(j).at(k)->SetInputs(sender_messages.at(i).at(j).at(k));
                    sender_ot.at(i).at(j).at(k)->SendMessages();
                  }
                }
              }
            }
          }
          motion_parties.at(i)->Finish();
        });
      }

      for (auto& t : threads) {
        t.join();
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        for (auto j = 0u; j < motion_parties.size(); ++j) {
          if (i != j) {
            for (auto k = 0ull; k < kNumberOfOts; ++k) {
              receiver_messages.at(i).at(j).at(k) = receiver_ot.at(i).at(j).at(k)->GetOutputs();
              sender_out.at(i).at(j).at(k) = sender_ot.at(i).at(j).at(k)->GetOutputs();
            }
          }
        }
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        for (auto j = 0u; j < motion_parties.size(); ++j) {
          if (i != j) {
            for (auto k = 0ull; k < kNumberOfOts; ++k) {
              for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
                if (!choices.at(j).at(i).at(k)[l]) {
                  ASSERT_EQ(receiver_messages.at(j).at(i).at(k).at(l),
                            sender_out.at(i).at(j).at(k).at(l).Subset(0, bitlength.at(k)));
                } else {
                  ASSERT_EQ(receiver_messages.at(j).at(i).at(k).at(l),
                            sender_out.at(i).at(j).at(k).at(l).Subset(bitlength.at(k),
                                                                      2 * bitlength.at(k)));
                  auto x = receiver_messages.at(j).at(i).at(k).at(l);
                  const auto mask = sender_out.at(i).at(j).at(k).at(l).Subset(0, bitlength.at(k));
                  if (bitlength.at(k) == 8u) {
                    *reinterpret_cast<std::uint8_t*>(x.GetMutableData().data()) -=
                        *reinterpret_cast<const std::uint8_t*>(mask.GetData().data());
                  } else if (bitlength.at(k) == 16u) {
                    *reinterpret_cast<std::uint16_t*>(x.GetMutableData().data()) -=
                        *reinterpret_cast<const std::uint16_t*>(mask.GetData().data());
                  } else if (bitlength.at(k) == 32u) {
                    *reinterpret_cast<std::uint32_t*>(x.GetMutableData().data()) -=
                        *reinterpret_cast<const std::uint32_t*>(mask.GetData().data());
                  } else if (bitlength.at(k) == 64u) {
                    *reinterpret_cast<std::uint64_t*>(x.GetMutableData().data()) -=
                        *reinterpret_cast<const std::uint64_t*>(mask.GetData().data());
                  } else if (bitlength.at(k) == 128u) {
                    *reinterpret_cast<__uint128_t*>(x.GetMutableData().data()) -=
                        *reinterpret_cast<const __uint128_t*>(mask.GetData().data());
                  }
                  ASSERT_EQ(x, sender_messages.at(i).at(j).at(k).at(l));
                }
              }
            }
          }
        }
      }
    } catch (std::exception& e) {
      std::cerr << e.what() << std::endl;
    }
  }
}

}  // namespace
