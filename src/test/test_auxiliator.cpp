#include <gtest/gtest.h>
#include <algorithm>

#include "base/party.h"
#include "protocols/share_wrapper.h"
#include "protocols/boolean_auxiliator/boolean_auxiliator_wire.h"
#include "test_constants.h"
#include "test_helpers.h"

#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/io.hpp>

constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max();
constexpr auto kAuxiliator = encrypto::motion::MpcProtocol::kAuxiliator;

namespace mo = encrypto::motion;
namespace ublas = boost::numeric::ublas;

template <typename T>
class AuxiliatorTest : public ::testing::Test {
 protected:
  void SetUp() override { InstantiateParties(); }

  void InstantiateParties() {
    parties_ = std::move(mo::MakeLocallyConnectedParties(number_of_parties_, kPortOffset));
    for (auto& party : parties_) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(true);
    }
  }

  void GenerateDiverseInputs() {
    zeros_single_.emplace_back(0);
    zeros_simd_.resize(number_of_simd_, 0);

    std::mt19937_64 mt(seed_);
    std::uniform_int_distribution<T> dist;

    for (T& t : inputs_single_) t = dist(mt);

    for (auto& v : inputs_simd_) {
      v.resize(number_of_simd_);
      for (T& t : v) t = dist(mt);
    }
  }

  void ShareDiverseInputs() {
    for (std::size_t input_owner : {0, 1, 2}) {
      for (std::size_t party_id : {0, 1, 2}) {
        if (party_id == input_owner) {
          shared_inputs_single_[party_id][input_owner] =
              parties_.at(party_id)->template In<kAuxiliator>(inputs_single_[input_owner], input_owner);
          shared_inputs_simd_[party_id][input_owner] =
              parties_.at(party_id)->template In<kAuxiliator>(inputs_simd_[input_owner], input_owner);
        } else {
          shared_inputs_single_[party_id][input_owner] =
              parties_.at(party_id)->template In<kAuxiliator>(zeros_single_, input_owner);
          shared_inputs_simd_[party_id][input_owner] =
              parties_.at(party_id)->template In<kAuxiliator>(zeros_simd_, input_owner);
        }
      }
    }
  }
  
  void SetToRandom(boost::numeric::ublas::matrix<T>& m) {
    for(size_t i = 0; i != m.size1(); ++i) {
      for(size_t j = 0; j != m.size2(); ++j) {
        m(i, j) = (i * m.size2() + j) % 2 == 0 ? 42 : -42;//dist_(mt_);
      }
    }
  }
  
  void GenerateMatrixInputs() {
    for (auto& m : matrix_inputs_single_) {
      m.resize(3, 3);
      SetToRandom(m);
    }
  }
  
  void ShareMatrixInputs() {
    for (std::size_t input_owner : {0, 1, 2}) {
      auto& input_matrix = matrix_inputs_single_[input_owner];
      for (std::size_t party_id : {0, 1, 2}) {
        auto& shared_matrix = shared_matrix_inputs_single_[party_id][input_owner];
        size_t m = input_matrix.size1();
        size_t n = input_matrix.size2();
        shared_matrix.resize(m, n);
        for(size_t i = 0; i != m; ++i) {
          for(size_t j = 0; j != n; ++j) {
            if(party_id == input_owner) {
              shared_matrix(i, j) = 
                parties_.at(party_id)->template In<kAuxiliator>(input_matrix(i, j), input_owner);
            } else {
              shared_matrix(i, j) = 
                parties_.at(party_id)->template In<kAuxiliator>(T(0), input_owner);
            }
          }
        }
      }
    }
  }

  static constexpr T seed_{0};
  static constexpr std::size_t number_of_simd_{1000};
  static constexpr std::size_t dot_product_vector_size_{100};
  std::mt19937_64 mt_{seed_};
  std::uniform_int_distribution<T> dist_;

  std::array<T, 3> inputs_single_;
  std::array<std::vector<T>, 3> inputs_simd_;
  std::array<std::vector<T>, 2> inputs_dot_product_single_;
  std::array<std::vector<std::vector<T>>, 2> inputs_dot_product_simd_;

  std::vector<T> zeros_single_;
  std::vector<T> zeros_simd_;

  static constexpr std::size_t number_of_parties_{3};
  std::vector<mo::PartyPointer> parties_;

  std::array<std::array<mo::ShareWrapper, 3>, 3> shared_inputs_single_;
  std::array<std::array<mo::ShareWrapper, 3>, 3> shared_inputs_simd_;

  std::array<std::array<std::vector<mo::ShareWrapper>, 2>, 3> shared_dot_product_inputs_single_;
  std::array<std::array<std::vector<mo::ShareWrapper>, 2>, 3> shared_dot_product_inputs_simd_;
  
  std::array<ublas::matrix<T>, 3> matrix_inputs_single_;
  std::array<std::array<ublas::matrix<mo::ShareWrapper>, 3>, 3> shared_matrix_inputs_single_;
};

using UintTypes = ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t>;
TYPED_TEST_SUITE(AuxiliatorTest, UintTypes);

TYPED_TEST(AuxiliatorTest, InputOutput) {
  this->GenerateDiverseInputs();
  this->ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id < this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      std::array<mo::ShareWrapper, 3> share_output_single, share_output_simd;
      for (std::size_t other_party_id = 0; other_party_id < this->number_of_parties_;
           ++other_party_id) {
        share_output_single[other_party_id] =
            this->shared_inputs_single_[party_id][other_party_id].Out(kAll);
        share_output_simd[other_party_id] =
            this->shared_inputs_simd_[party_id][other_party_id].Out(kAll);
      }

      this->parties_[party_id]->Run();

      for (std::size_t input_owner = 0; input_owner < this->number_of_parties_; ++input_owner) {
        EXPECT_EQ(share_output_single[input_owner].template As<TypeParam>(),
                  this->inputs_single_[input_owner]);
        EXPECT_EQ(share_output_simd[input_owner].template As<std::vector<TypeParam>>(),
                  this->inputs_simd_[input_owner]);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TYPED_TEST(AuxiliatorTest, Addition) {
  this->GenerateDiverseInputs();
  this->ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id < this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_add_single = this->shared_inputs_single_[party_id][0] +
                              this->shared_inputs_single_[party_id][1] +
                              this->shared_inputs_single_[party_id][2];
      auto share_add_simd = this->shared_inputs_simd_[party_id][0] +
                            this->shared_inputs_simd_[party_id][1] +
                            this->shared_inputs_simd_[party_id][2];

      auto share_output_single_all = share_add_single.Out();
      auto share_output_simd_all = share_add_simd.Out();

      this->parties_[party_id]->Run();

      {
        TypeParam circuit_result_single = share_output_single_all.template As<TypeParam>();
        TypeParam expected_result_single = mo::SumReduction<TypeParam>(this->inputs_single_);
        EXPECT_EQ(circuit_result_single, expected_result_single);

        const std::vector<TypeParam> circuit_result_simd =
            share_output_simd_all.template As<std::vector<TypeParam>>();
        const std::vector<TypeParam> expected_result_simd =
            std::move(mo::RowSumReduction<TypeParam>(this->inputs_simd_));
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TYPED_TEST(AuxiliatorTest, Subtraction) {
  this->GenerateDiverseInputs();
  this->ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id < this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_sub_single = this->shared_inputs_single_[party_id][0] -
                              this->shared_inputs_single_[party_id][1] -
                              this->shared_inputs_single_[party_id][2];
      auto share_sub_simd = this->shared_inputs_simd_[party_id][0] -
                            this->shared_inputs_simd_[party_id][1] -
                            this->shared_inputs_simd_[party_id][2];

      auto share_output_single_all = share_sub_single.Out();
      auto share_output_simd_all = share_sub_simd.Out();

      this->parties_[party_id]->Run();

      {
        TypeParam circuit_result_single = share_output_single_all.template As<TypeParam>();
        TypeParam expected_result_single = mo::SubReduction<TypeParam>(this->inputs_single_);
        EXPECT_EQ(circuit_result_single, expected_result_single);

        const std::vector<TypeParam> circuit_result_simd =
            share_output_simd_all.template As<std::vector<TypeParam>>();
        const std::vector<TypeParam> expected_result_simd =
            std::move(mo::RowSubReduction<TypeParam>(this->inputs_simd_));
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TYPED_TEST(AuxiliatorTest, Multiplication) {
  this->GenerateDiverseInputs();
  this->ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id < this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mul_single = this->shared_inputs_single_[party_id][0] *
                              this->shared_inputs_single_[party_id][1] *
                              this->shared_inputs_single_[party_id][2];
      auto share_mul_simd = this->shared_inputs_simd_[party_id][0] *
                            this->shared_inputs_simd_[party_id][1] *
                            this->shared_inputs_simd_[party_id][2];

      auto share_output_single_all = share_mul_single.Out();
      auto share_output_simd_all = share_mul_simd.Out();

      this->parties_[party_id]->Run();

      {
        TypeParam circuit_result_single = share_output_single_all.template As<TypeParam>();
        TypeParam expected_result_single = mo::MulReduction<TypeParam>(this->inputs_single_);
        EXPECT_EQ(circuit_result_single, expected_result_single);

        const std::vector<TypeParam> circuit_result_simd =
            share_output_simd_all.template As<std::vector<TypeParam>>();
        const std::vector<TypeParam> expected_result_simd =
            std::move(mo::RowMulReduction<TypeParam>(this->inputs_simd_));
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TYPED_TEST(AuxiliatorTest, MatrixMultiplication) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::auxiliator;
  
  this->GenerateMatrixInputs();
  this->ShareMatrixInputs();
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mm_single = mo::MatrixMultiplication(
                               mo::MatrixMultiplication(
                                 this->shared_matrix_inputs_single_[party_id][0],
                                 this->shared_matrix_inputs_single_[party_id][1]), 
                               this->shared_matrix_inputs_single_[party_id][2]);
                                                      
      size_t m = share_mm_single.size1();
      size_t n = share_mm_single.size2();

      ublas::matrix<mo::ShareWrapper> out_share_matrix_single(m, n);
      
      for(size_t i = 0; i != m; ++i) {
        for(size_t j = 0; j != n; ++j) {
          out_share_matrix_single(i, j) = share_mm_single(i, j).Out();
        }
      }

      this->parties_[party_id]->Run();
      
      ublas::matrix<TypeParam> circuit_result_matrix_single(m, n);
      
      for(size_t i = 0; i != m; ++i) {
        for(size_t j = 0; j != n; ++j) {
          circuit_result_matrix_single(i, j) = out_share_matrix_single(i, j).template As<TypeParam>();
        }
      }

      {
        ublas::matrix<TypeParam> expected_result_single = 
          prod(this->matrix_inputs_single_[0], this->matrix_inputs_single_[1]);
        expected_result_single = prod(expected_result_single, this->matrix_inputs_single_[2]);
          
        EXPECT_PRED2(
        [](auto const& a, auto const& b){
          if(a.size1() != b.size1()) return false;
          if(a.size2() != b.size2()) return false;
          for(size_t i = 0; i != a.size1(); ++i) {
            for(size_t j = 0; j != a.size2(); ++j) {
              if(a(i, j) != b(i, j)) return false;
            }
          }
          return true;
        }, 
        circuit_result_matrix_single, expected_result_single);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

template<typename T>
struct FixedPoint {
  FixedPoint() = default;  

  FixedPoint(T const& value, unsigned precision = sizeof(T) * 2)
  : value(value << precision), precision(precision) {}
  
  FixedPoint& operator+=(FixedPoint const& other) {
    value += other.value;
    return *this;
  }
  
  FixedPoint& operator-=(FixedPoint const& other) {
    value -= other.value;
    return *this;
  }
  
  FixedPoint& operator*=(FixedPoint const& other) {
    value *= other.value;
    std::make_unsigned_t<T> signed_value = value;
    value >>= precision;
    return *this;
  }
  
  T value;
  unsigned precision;
};

template<typename T>
FixedPoint<T> operator+(FixedPoint<T> const& rhs, FixedPoint<T> const& lhs) {
  FixedPoint result(rhs);
  result += lhs;
  return result;
}
template<typename T>
FixedPoint<T> operator-(FixedPoint<T> const& rhs, FixedPoint<T> const& lhs) {
  FixedPoint result(rhs);
  result -= lhs;
  return result;
}
template<typename T>
FixedPoint<T> operator*(FixedPoint<T> const& rhs, FixedPoint<T> const& lhs) {
  FixedPoint result(rhs);
  result *= lhs;
  return result;
}

template<typename T>
std::ostream& operator<<(std::ostream& os, FixedPoint<T> const& fp) {
  return os << fp.value;
}


TYPED_TEST(AuxiliatorTest, FixedPointMatrixMultiplication) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::auxiliator;
  
  this->GenerateMatrixInputs();
  this->ShareMatrixInputs();
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mm_single = mo::FixedPointMatrixMultiplication(
                               mo::FixedPointMatrixMultiplication(
                                 this->shared_matrix_inputs_single_[party_id][0],
                                 this->shared_matrix_inputs_single_[party_id][1], 
                                 sizeof(TypeParam) * 2), 
                               this->shared_matrix_inputs_single_[party_id][2], 
                               sizeof(TypeParam) * 2);
                                                      
      size_t m = share_mm_single.size1();
      size_t n = share_mm_single.size2();

      ublas::matrix<mo::ShareWrapper> out_share_matrix_single(m, n);
      
      for(size_t i = 0; i != m; ++i) {
        for(size_t j = 0; j != n; ++j) {
          out_share_matrix_single(i, j) = share_mm_single(i, j).Out();
        }
      }

      this->parties_[party_id]->Run();
      
      ublas::matrix<TypeParam> circuit_result_matrix_single(m, n);
      
      for(size_t i = 0; i != m; ++i) {
        for(size_t j = 0; j != n; ++j) {
          circuit_result_matrix_single(i, j) = out_share_matrix_single(i, j).template As<TypeParam>();
        }
      }

      {
        ublas::matrix<TypeParam> expected_result_single;
          
        EXPECT_PRED2(
        [](auto const& a, auto const& b){
          return true;
        }, 
        circuit_result_matrix_single, expected_result_single);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}


TYPED_TEST(AuxiliatorTest, HadamardMultiplication) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::auxiliator;
  
  this->GenerateMatrixInputs();
  this->ShareMatrixInputs();
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mm_single = mo::HadamardMultiplication(
                               mo::HadamardMultiplication(
                                 this->shared_matrix_inputs_single_[party_id][0],
                                 this->shared_matrix_inputs_single_[party_id][1]), 
                               this->shared_matrix_inputs_single_[party_id][2]);
                                                      
      size_t m = share_mm_single.size1();
      size_t n = share_mm_single.size2();

      ublas::matrix<mo::ShareWrapper> out_share_matrix_single(m, n);
      
      for(size_t i = 0; i != m; ++i) {
        for(size_t j = 0; j != n; ++j) {
          out_share_matrix_single(i, j) = share_mm_single(i, j).Out();
        }
      }

      this->parties_[party_id]->Run();
      
      ublas::matrix<TypeParam> circuit_result_matrix_single(m, n);
      
      for(size_t i = 0; i != m; ++i) {
        for(size_t j = 0; j != n; ++j) {
          circuit_result_matrix_single(i, j) = out_share_matrix_single(i, j).template As<TypeParam>();
        }
      }

      {
        ublas::matrix<TypeParam> expected_result_single = this->matrix_inputs_single_[0];
        
        for(size_t i = 0; i != m; ++i) {
          for(size_t j = 0; j != n; ++j) {
            expected_result_single(i, j) *= this->matrix_inputs_single_[1](i, j) * 
                                            this->matrix_inputs_single_[2](i, j);
          }
        }
          
        EXPECT_PRED2(
        [](auto const& a, auto const& b){
          if(a.size1() != b.size1()) return false;
          if(a.size2() != b.size2()) return false;
          for(size_t i = 0; i != a.size1(); ++i) {
            for(size_t j = 0; j != a.size2(); ++j) {
              if(a(i, j) != b(i, j)) return false;
            }
          }
          return true;
        }, 
        circuit_result_matrix_single, expected_result_single);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

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

}

TYPED_TEST(AuxiliatorTest, Msb) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::auxiliator;
  
  this->GenerateMatrixInputs();
  this->ShareMatrixInputs();
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mm_single = mo::MatrixMsb(
        this->shared_matrix_inputs_single_[party_id][0]);
                                                      
      size_t m = this->shared_matrix_inputs_single_[party_id][0].size1();
      size_t n = this->shared_matrix_inputs_single_[party_id][0].size2();

      ublas::matrix<mo::ShareWrapper> out_share_matrix_single(m, n);
      auto out_share_single = share_mm_single.Out();
      
      this->parties_[party_id]->Run();
      
      std::vector<std::byte> circuit_result = ToByteVector(out_share_single);
      
      {
        mo::BitVector<> expected_result_single(n*m, false);
        for(size_t i = 0; i != m; ++i) {
          for(size_t j = 0; j != n; ++j) {
            expected_result_single.Set(bool((this->matrix_inputs_single_[0](i, j) >> (sizeof(TypeParam) * CHAR_BIT - 1))), i*n + j);
          }
        }
        expected_result_single.Invert();
          
        EXPECT_EQ(ToByteVector(out_share_single), expected_result_single.GetData());
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TYPED_TEST(AuxiliatorTest, ReLU) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::auxiliator;
  
  this->GenerateMatrixInputs();
  this->ShareMatrixInputs();
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mm_single = mo::ReLU(
        this->shared_matrix_inputs_single_[party_id][0]);
                                                      
      size_t m = this->shared_matrix_inputs_single_[party_id][0].size1();
      size_t n = this->shared_matrix_inputs_single_[party_id][0].size2();
      
      mo::ShareWrapper result_mm_single = share_mm_single.Out();
      
      this->parties_[party_id]->Run();
      
      ublas::matrix<TypeParam> circuit_result_matrix_single(m, n);
      std::vector<TypeParam> result = result_mm_single.template As<std::vector<TypeParam>>();
      
      {
        size_t offset = 0;
        for(size_t i = 0; i != m; ++i) {
          for(size_t j = 0; j != n; ++j) {
            circuit_result_matrix_single(i, j) = result[offset];
            ++offset;
          }
        }
      }
      
      {
        ublas::matrix<TypeParam> expected_result_single(m, n);
        for(size_t i = 0; i != m; ++i) {
          for(size_t j = 0; j != n; ++j) {
            if(bool((this->matrix_inputs_single_[0](i, j) >> (sizeof(TypeParam) * CHAR_BIT - 1)))) {
              expected_result_single(i, j) = 0;
            } else {
              expected_result_single(i, j) = this->matrix_inputs_single_[0](i, j);
            }
          }
        }
          
        EXPECT_PRED2(
        [](auto const& a, auto const& b){
          if(a.size1() != b.size1()) return false;
          if(a.size2() != b.size2()) return false;
          for(size_t i = 0; i != a.size1(); ++i) {
            for(size_t j = 0; j != a.size2(); ++j) {
              if(a(i, j) != b(i, j)) return false;
            }
          }
          return true;
        }, 
        circuit_result_matrix_single, expected_result_single);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}