#include <gtest/gtest.h>
#include <algorithm>

#include "base/party.h"
#include "protocols/share_wrapper.h"
#include "protocols/boolean_auxiliator/boolean_auxiliator_wire.h"
#include "protocols/boolean_auxiliator/boolean_auxiliator_gate.h"
#include "test_constants.h"
#include "test_helpers.h"
#include "utility/bit_vector.h"

constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max();
constexpr auto kBooleanAuxiliator = encrypto::motion::MpcProtocol::kBooleanAuxiliator;

namespace mo = encrypto::motion;

class BooleanAuxiliatorTestParameters {
 
 public:
  BooleanAuxiliatorTestParameters() { InstantiateParties(); }

  void InstantiateParties() {
    parties_ = std::move(mo::MakeLocallyConnectedParties(number_of_parties_, kPortOffset));
    for (auto& party : parties_) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(true);
    }
  }

  void GenerateDiverseInputs() {
    zeros_single_.resize(kDefaultTestBitLength, mo::BitVector<>(1, false));
    zeros_simd_.resize(kDefaultTestBitLength, mo::BitVector<>(number_of_simd_, false));

    for (auto& v : inputs_single_) {
      v.resize(kDefaultTestBitLength);
      for (mo::BitVector<>& t : v) {
        t = mo::BitVector<>::SecureRandom(1);
      }
    }

    for (auto& v : inputs_simd_) {
      v.resize(kDefaultTestBitLength);
      for (mo::BitVector<>& t : v) {
        t = mo::BitVector<>::SecureRandom(number_of_simd_);
      }
    }
  }

  void ShareDiverseInputs() {
    for (std::size_t input_owner : {0, 1, 2}) {
      for (std::size_t party_id : {0, 1, 2}) {
        if (party_id == input_owner) {
          shared_inputs_single_[party_id][input_owner] =
              parties_.at(party_id)->template In<kBooleanAuxiliator>(inputs_single_[input_owner], input_owner);
          shared_inputs_simd_[party_id][input_owner] =
              parties_.at(party_id)->template In<kBooleanAuxiliator>(inputs_simd_[input_owner], input_owner);
        } else {
          shared_inputs_single_[party_id][input_owner] =
              parties_.at(party_id)->template In<kBooleanAuxiliator>(zeros_single_, input_owner);
          shared_inputs_simd_[party_id][input_owner] =
              parties_.at(party_id)->template In<kBooleanAuxiliator>(zeros_simd_, input_owner);
        }
      }
    }
  }
  
  void GenerateAndNInputs(size_t arity) {
    zeros_single_.emplace_back(kDefaultTestBitLength, false);
    zeros_simd_.resize(number_of_simd_, mo::BitVector<>(kDefaultTestBitLength, false));

    for (auto& v : inputs_and_n_) {
      v.resize(arity);
      for (mo::BitVector<>& t : v) {
        t = mo::BitVector<>::SecureRandom(kDefaultTestBitLength);
      }
    }
  }
  
  void ShareAndNInputs() {
    //Input owner is always 0
    size_t input_owner = 0;
    size_t arity = inputs_and_n_[0].size();
    for (std::size_t party_id : {0, 1, 2}) {
      shared_and_n_inputs_[party_id].reserve(arity);
      for(size_t i = 0; i != arity; ++i) {
        if (party_id == input_owner) {
        shared_and_n_inputs_[party_id].emplace_back(
            parties_.at(party_id)->template In<kBooleanAuxiliator>(inputs_and_n_[0][i], input_owner));
        /*shared_inputs_simd_[party_id][input_owner] =
            parties_.at(party_id)->template In<kBooleanAuxiliator>(inputs_simd_[input_owner], input_owner);*/
        
        } else {
          shared_and_n_inputs_[party_id].emplace_back(
              parties_.at(party_id)->template In<kBooleanAuxiliator>(zeros_single_, input_owner));
          /*shared_inputs_simd_[party_id][input_owner] =
              parties_.at(party_id)->template In<kBooleanAuxiliator>(zeros_simd_, input_owner);*/
        }
      }
    }
  }

  
  void GenerateDotProductInputs() {
    zeros_single_.emplace_back(kDefaultTestBitLength, false);
    zeros_simd_.resize(number_of_simd_, mo::BitVector<>(kDefaultTestBitLength, false));

    for (auto& v : inputs_dot_product_single_) {
      v.resize(dot_product_vector_size_);
      for (mo::BitVector<>& t : v) {
        t = mo::BitVector<>::SecureRandom(kDefaultTestBitLength);
      }
    }

    for (auto& vv : inputs_dot_product_simd_) {
      vv.resize(dot_product_vector_size_);
      for (auto& v : vv) {
        v.resize(number_of_simd_);
        for (mo::BitVector<>& t : v) {
          t = mo::BitVector<>::SecureRandom(kDefaultTestBitLength);
        }
      }
    }
  }
  
  void ShareDotProductInputs() {
    constexpr std::size_t input_owner = 0;
    for (std::size_t party_id : {0, 1, 2}) {
      for (std::size_t vector_i : {0, 1}) {
        shared_dot_product_inputs_single_[party_id][vector_i].resize(dot_product_vector_size_);
        shared_dot_product_inputs_simd_[party_id][vector_i].resize(dot_product_vector_size_);
        for (std::size_t element_j = 0; element_j < dot_product_vector_size_; ++element_j) {
          shared_dot_product_inputs_single_[party_id][vector_i][element_j] =
              parties_.at(party_id)->template In<kBooleanAuxiliator>(
                  inputs_dot_product_single_[vector_i][element_j], input_owner);
          shared_dot_product_inputs_simd_[party_id][vector_i][element_j] =
              parties_.at(party_id)->template In<kBooleanAuxiliator>(
                  inputs_dot_product_simd_[vector_i][element_j], input_owner);
        }
      }
    }
  }
  
  std::vector<std::byte> GetXorOfInputs() const {
    std::vector<mo::BitVector<>> xored = inputs_single_[0];
    for(size_t party_id = 1u; party_id != parties_.size(); ++party_id) {
      for(size_t i = 0u; i != xored.size(); ++i) {
        xored[i] ^= inputs_single_[party_id][i];
      }
    }
    std::vector<std::byte> result;
    for(auto& b : xored) {
      auto& d = b.GetData();
      std::copy(d.begin(), d.end(), std::back_inserter(result));
    }
    return result;
  }
  
  std::vector<std::byte> GetXorOfSimdInputs() const {
    std::vector<mo::BitVector<>> xored = inputs_simd_[0];
    for(size_t party_id = 1u; party_id != parties_.size(); ++party_id) {
      for(size_t i = 0u; i != xored.size(); ++i) {
        xored[i] ^= inputs_simd_[party_id][i];
      }
    }
    std::vector<std::byte> result;
    for(auto& b : xored) {
      auto& d = b.GetData();
      std::copy(d.begin(), d.end(), std::back_inserter(result));
    }
    return result;
  }
  
  std::vector<std::byte> GetAndOfInputs() const {
    std::vector<mo::BitVector<>> anded = inputs_single_[0];
    for(size_t party_id = 1u; party_id != parties_.size(); ++party_id) {
      for(size_t i = 0u; i != anded.size(); ++i) {
        anded[i] &= inputs_single_[party_id][i];
      }
    }
    std::vector<std::byte> result;
    for(auto& b : anded) {
      auto& d = b.GetData();
      std::copy(d.begin(), d.end(), std::back_inserter(result));
    }
    return result;
  }
  
  std::vector<std::byte> GetAndOfSimdInputs() const {
    std::vector<mo::BitVector<>> anded = inputs_simd_[0];
    for(size_t party_id = 1u; party_id != parties_.size(); ++party_id) {
      for(size_t i = 0u; i != anded.size(); ++i) {
        anded[i] &= inputs_simd_[party_id][i];
      }
    }
    std::vector<std::byte> result;
    for(auto& b : anded) {
      auto& d = b.GetData();
      std::copy(d.begin(), d.end(), std::back_inserter(result));
    }
    return result;
  }
  
  std::vector<std::byte> GetAndNOfInputs() const {
    mo::BitVector<> result = inputs_and_n_[0][0];
    for(size_t i = 0; i != inputs_and_n_[0].size(); ++i) {
      result &= inputs_and_n_[0][i];
    }
    
    return result.GetData();
  }
  
  mo::BitVector<> DotProduct(std::vector<mo::BitVector<>> const& x, std::vector<mo::BitVector<>> const& y) const {
    assert(x.size() == y.size());
    mo::BitVector<> result = x[0] & y[0];
    for(size_t i = 1u; i != x.size(); ++i) {
      result ^= x[i] & y[i];
    }
    return result;
  }
  
  std::vector<mo::BitVector<>> 
  SimdDotProduct(std::vector<std::vector<mo::BitVector<>>> const& x, 
                 std::vector<std::vector<mo::BitVector<>>> const& y) const {
    std::vector<mo::BitVector<>> result;
    for(size_t i = 0u; i != number_of_simd_; ++i) {
      mo::BitVector<> b = x[0][i] & y[0][i];
      for(size_t j = 1u; j != dot_product_vector_size_; ++j) {
        b ^= x[j][i] & y[j][i];
      }
      result.emplace_back(std::move(b));
    }
    return result;
  }
  
  std::vector<std::byte> GetDotProductOfInputs() const {
    return DotProduct(inputs_dot_product_single_[0], inputs_dot_product_single_[1]).GetData();
  }
  
  std::vector<std::byte> GetDotProductOfSimdInputs() const {
    std::vector<mo::BitVector<>> dot_product = 
      SimdDotProduct(inputs_dot_product_simd_[0], inputs_dot_product_simd_[1]);
    std::vector<std::byte> result;
    for(auto& b : dot_product) {
      auto& d = b.GetData();
      std::copy(d.begin(), d.end(), std::back_inserter(result));
    }
    return result;
  }
  static constexpr size_t kDefaultTestBitLength = 32;
  static constexpr std::size_t number_of_simd_ = 1000;
  static constexpr std::size_t dot_product_vector_size_ = 100;

  std::array<std::vector<mo::BitVector<>>, 3> inputs_single_;
  std::array<std::vector<mo::BitVector<>>, 3> inputs_simd_;
  std::array<std::vector<mo::BitVector<>>, 2> inputs_dot_product_single_;
  std::array<std::vector<std::vector<mo::BitVector<>>>, 2> inputs_dot_product_simd_;
  
  //Dimensions: inputs_and_n_[PARTY][ARGUMENT_ID]
  std::array<std::vector<mo::BitVector<>>, 3> inputs_and_n_;
  //Dimensions: shared_and_n_inputs_[PARTY_ID][ARGUMENT_ID]
  std::array<std::vector<mo::ShareWrapper>, 3> shared_and_n_inputs_;

  std::vector<mo::BitVector<>> zeros_single_;
  std::vector<mo::BitVector<>> zeros_simd_;

  static constexpr std::size_t number_of_parties_{3};
  std::vector<mo::PartyPointer> parties_;

  std::array<std::array<mo::ShareWrapper, 3>, 3> shared_inputs_single_;
  std::array<std::array<mo::ShareWrapper, 3>, 3> shared_inputs_simd_;

  std::array<std::array<std::vector<mo::ShareWrapper>, 2>, 3> shared_dot_product_inputs_single_;
  std::array<std::array<std::vector<mo::ShareWrapper>, 2>, 3> shared_dot_product_inputs_simd_;
};

namespace {

std::vector<std::byte> ToByteVector(mo::ShareWrapper output) {
  std::vector<std::byte> result;
  auto wires = output->GetWires();
  for(auto& wire : wires) {
    auto w = std::dynamic_pointer_cast<mo::proto::boolean_auxiliator::Wire>(wire);
    auto& d = w->GetValues().GetData();
    std::copy(d.begin(), d.end(), std::back_inserter(result));
  }
  return result;
}

}  // namespace (anonymous) 

TEST(BooleanAuxiliatorTest, InputOutput) {
  BooleanAuxiliatorTestParameters auxiliator_test;
  auxiliator_test.GenerateDiverseInputs();
  auxiliator_test.ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != auxiliator_test.parties_.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      std::array<mo::ShareWrapper, 3> share_output_single, share_output_simd;
      for (std::size_t other_party_id = 0u; 
           other_party_id != auxiliator_test.number_of_parties_;
           ++other_party_id) {
        share_output_single[other_party_id] =
            auxiliator_test.shared_inputs_single_[party_id][other_party_id].Out(kAll);
        share_output_simd[other_party_id] =
            auxiliator_test.shared_inputs_simd_[party_id][other_party_id].Out(kAll);
      }

      auxiliator_test.parties_[party_id]->Run();

      for (std::size_t input_owner = 0; input_owner != auxiliator_test.number_of_parties_; ++input_owner) {
        std::vector<std::byte> expected_result_single;
        for(auto& s : auxiliator_test.inputs_single_[input_owner]) {
          auto& d = s.GetData();
          std::copy(d.begin(), d.end(), std::back_inserter(expected_result_single));
        }
        std::vector<std::byte> circuit_result_single = ToByteVector(share_output_single[input_owner]);
        EXPECT_EQ(circuit_result_single, expected_result_single);
        std::vector<std::byte> circuit_result_simd = ToByteVector(share_output_simd[input_owner]);
        std::vector<std::byte> expected_result_simd;
        for(auto& s : auxiliator_test.inputs_simd_[input_owner]) {
          auto& d = s.GetData();
          std::copy(d.begin(), d.end(), std::back_inserter(expected_result_simd));
        }
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      auxiliator_test.parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TEST(BooleanAuxiliatorTest, Xor) {
  BooleanAuxiliatorTestParameters auxiliator_test;
  auxiliator_test.GenerateDiverseInputs();
  auxiliator_test.ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != auxiliator_test.parties_.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      auto share_xor_single = auxiliator_test.shared_inputs_single_[party_id][0] ^
                              auxiliator_test.shared_inputs_single_[party_id][1] ^
                              auxiliator_test.shared_inputs_single_[party_id][2];
      auto share_xor_simd = auxiliator_test.shared_inputs_simd_[party_id][0] ^
                            auxiliator_test.shared_inputs_simd_[party_id][1] ^
                            auxiliator_test.shared_inputs_simd_[party_id][2];

      auto share_output_single_all = share_xor_single.Out();
      auto share_output_simd_all = share_xor_simd.Out();

      auxiliator_test.parties_[party_id]->Run();

      {
        std::vector<std::byte> circuit_result_single = ToByteVector(share_output_single_all);
        std::vector<std::byte> expected_result_single = auxiliator_test.GetXorOfInputs();
        EXPECT_EQ(circuit_result_single, expected_result_single);

        const std::vector<std::byte> circuit_result_simd = ToByteVector(share_output_simd_all);
        const std::vector<std::byte> expected_result_simd = auxiliator_test.GetXorOfSimdInputs();
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      auxiliator_test.parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TEST(BooleanAuxiliatorTest, And) {
  BooleanAuxiliatorTestParameters auxiliator_test;
  auxiliator_test.GenerateDiverseInputs();
  auxiliator_test.ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != auxiliator_test.parties_.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      auto share_and_single = auxiliator_test.shared_inputs_single_[party_id][0] &
                              auxiliator_test.shared_inputs_single_[party_id][1] &
                              auxiliator_test.shared_inputs_single_[party_id][2];
      auto share_and_simd = auxiliator_test.shared_inputs_simd_[party_id][0] &
                            auxiliator_test.shared_inputs_simd_[party_id][1] &
                            auxiliator_test.shared_inputs_simd_[party_id][2];

      auto share_output_single_all = share_and_single.Out();
      auto share_output_simd_all = share_and_simd.Out();

      auxiliator_test.parties_[party_id]->Run();

      {
        std::vector<std::byte> circuit_result_single = ToByteVector(share_output_single_all);
        std::vector<std::byte> expected_result_single = auxiliator_test.GetAndOfInputs();
        EXPECT_EQ(circuit_result_single, expected_result_single);

        const std::vector<std::byte> circuit_result_simd = ToByteVector(share_output_simd_all);
        const std::vector<std::byte> expected_result_simd = auxiliator_test.GetAndOfSimdInputs();
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      auxiliator_test.parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TEST(BooleanAuxiliatorTest, Add) {
  BooleanAuxiliatorTestParameters auxiliator_test;
  auxiliator_test.GenerateDiverseInputs();
  auxiliator_test.ShareDiverseInputs();
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != auxiliator_test.parties_.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      auto share_msb_single = 
        MsbAdd(auxiliator_test.shared_inputs_single_[party_id][0],
               auxiliator_test.shared_inputs_single_[party_id][1]);
      auto share_msb_simd = 
        MsbAdd(auxiliator_test.shared_inputs_simd_[party_id][0],
               auxiliator_test.shared_inputs_simd_[party_id][1]);

      auto share_output_single_all = share_msb_single.Out();
      auto share_output_simd_all = share_msb_simd.Out();

      auxiliator_test.parties_[party_id]->Run();

      {
        std::vector<mo::BitVector<>> a_v = auxiliator_test.inputs_single_[0];
        std::vector<mo::BitVector<>> b_v = auxiliator_test.inputs_single_[1];
        uint32_t a = 0, b = 0;
        for(size_t i = 0; i != a_v.size(); ++i) {
          a |= uint32_t(a_v[i].Get(0)) << i;
          b |= uint32_t(b_v[i].Get(0)) << i;
          EXPECT_EQ(a_v[i].GetSize(), 1);
          EXPECT_EQ(b_v[i].GetSize(), 1);
        }
        std::vector<std::byte> circuit_result_single = ToByteVector(share_output_single_all);
        std::vector<std::byte> expected_result_single{std::byte((a + b) >> 31)};
        EXPECT_EQ(circuit_result_single, expected_result_single);
        
        auto const& a_vectors = auxiliator_test.inputs_simd_[0];
        auto const& b_vectors = auxiliator_test.inputs_simd_[1];
        size_t n = a_vectors[0].GetSize();
        mo::BitVector<> expected_result_simd;
        for(size_t s = 0; s != n; ++s) {
          a = 0; b = 0;
          for(size_t i = 0; i != a_vectors.size(); ++i) {
            a |= uint32_t(a_vectors[i].Get(s)) << i;
            b |= uint32_t(b_vectors[i].Get(s)) << i;
            EXPECT_EQ(a_vectors[i].GetSize(), n);
            EXPECT_EQ(b_vectors[i].GetSize(), n);
          }
          expected_result_simd.Append(bool((a + b) >> 31));
        }
        const std::vector<std::byte> circuit_result_simd = ToByteVector(share_output_simd_all);
        EXPECT_EQ(circuit_result_simd, expected_result_simd.GetData());
        
      }
      auxiliator_test.parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}