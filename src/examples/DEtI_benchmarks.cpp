#include "base/party.h"
#include "protocols/share_wrapper.h"
#include "protocols/boolean_astra/boolean_astra_wire.h"

#include "DEtI_benchmarks.h"

#include "base/party.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "protocols/astra/astra_wire.h"
#include "protocols/astra/astra_share.h"
#include "protocols/auxiliator/auxiliator_wire.h"
#include "protocols/auxiliator/auxiliator_share.h"
#include "protocols/swift/swift_wire.h"
#include "protocols/swift/swift_gate.h"
#include "protocols/socium/socium_wire.h"
#include "protocols/socium/socium_gate.h"
#include "statistics/analysis.h"
#include "utility/typedefs.h"
#include "communication/transport.h"
#include "primitives/sharing_randomness_generator.h"
#include "primitives/blake2b.h"
#include "communication/message_manager.h"
#include "communication/message.h"

using namespace encrypto::motion;
using namespace encrypto::motion::communication;

using namespace boost::numeric;
using TypeParam = uint64_t;

bool CheckPartyArgumentSyntax(const std::string& party_argument);

std::pair<program_options::variables_map, bool> ParseProgramOptions(int ac, char* av[]);

encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options);

ublas::matrix<ShareWrapper> 
AstraMakeDummyInputMatrix(PartyPointer& party, size_t m, size_t n) {
  auto backend = party->GetBackend();
  auto reg = backend->GetRegister();
  
  ublas::matrix<ShareWrapper> result(m, n);
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      auto w = reg->template EmplaceWire<proto::astra::Wire<TypeParam>>(
        *backend, std::vector<proto::astra::Wire<TypeParam>::Data>{{42, 42, 42}});
      result(i, j) = ShareWrapper(std::make_shared<proto::astra::Share<TypeParam>>(w));
      w->SetSetupIsReady();
      w->SetOnlineFinished();
    }
  }
  return result;
}

ublas::matrix<ShareWrapper> 
AuxiliatorMakeDummyInputMatrix(PartyPointer& party, size_t m, size_t n) {
  auto backend = party->GetBackend();
  auto reg = backend->GetRegister();
  
  ublas::matrix<ShareWrapper> result(m, n);
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      auto w = reg->template EmplaceWire<proto::auxiliator::Wire<TypeParam>>(
        *backend, std::vector<proto::auxiliator::Wire<TypeParam>::Data>{{42, 42, 42}});
      result(i, j) = ShareWrapper(std::make_shared<proto::auxiliator::Share<TypeParam>>(w));
      w->SetSetupIsReady();
      w->SetOnlineFinished();
    }
  }
  return result;
}

ublas::matrix<proto::swift::WirePointer<TypeParam>> 
SwiftMakeDummyInputMatrix(PartyPointer& party, size_t m, size_t n) {
  auto backend = party->GetBackend();
  auto reg = backend->GetRegister();
  
  ublas::matrix<proto::swift::WirePointer<TypeParam>> result(m, n);
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      std::vector<TypeParam> v1{42}, v2{42}, v3{42};
      auto w = reg->template EmplaceWire<proto::swift::Wire<TypeParam>>(
        *backend, 1, v1, v2, v3);
      result(i, j) = w;
      w->SetSetupIsReady();
      w->SetOnlineFinished();
    }
  }
  return result;
}

ublas::matrix<proto::socium::WirePointer<TypeParam>> 
SociumMakeDummyInputMatrix(PartyPointer& party, size_t m, size_t n) {
  auto backend = party->GetBackend();
  auto reg = backend->GetRegister();
  
  ublas::matrix<proto::socium::WirePointer<TypeParam>> result(m, n);
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      std::vector<TypeParam> v1{42}, v2{42}, v3{42};
      auto w = reg->template EmplaceWire<proto::socium::Wire<TypeParam>>(
        *backend, 1, v1, v2, v3);
      result(i, j) = w;
      w->SetSetupIsReady();
      w->SetOnlineFinished();
    }
  }
  return result;
}

ublas::matrix<ShareWrapper> AstraMakeDummyInputSimdMatrices(
  PartyPointer& party, size_t m, size_t n, size_t number_of_simd_values) {
  auto backend = party->GetBackend();
  auto reg = backend->GetRegister();
  
  ublas::matrix<ShareWrapper> result(m, n);
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      std::vector<proto::astra::Wire<TypeParam>::Data> simd_input;
      simd_input.reserve(number_of_simd_values);
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        simd_input.emplace_back(42, 42, 42);
      }
      auto w = reg->template EmplaceWire<proto::astra::Wire<TypeParam>>(*backend, simd_input);
      result(i, j) = ShareWrapper(std::make_shared<proto::astra::Share<TypeParam>>(w));
      w->SetSetupIsReady();
      w->SetOnlineFinished();
    }
  }
  return result;
}

ublas::matrix<ShareWrapper> AuxiliatorMakeDummyInputSimdMatrices(
  PartyPointer& party, size_t m, size_t n, size_t number_of_simd_values) {
  auto backend = party->GetBackend();
  auto reg = backend->GetRegister();
  
  ublas::matrix<ShareWrapper> result(m, n);
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      std::vector<proto::auxiliator::Wire<TypeParam>::Data> simd_input;
      simd_input.reserve(number_of_simd_values);
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        simd_input.emplace_back(42, 42, 42);
      }
      auto w = reg->template EmplaceWire<proto::auxiliator::Wire<TypeParam>>(*backend, simd_input);
      result(i, j) = ShareWrapper(std::make_shared<proto::auxiliator::Share<TypeParam>>(w));
      w->SetSetupIsReady();
      w->SetOnlineFinished();
    }
  }
  return result;
}

ublas::matrix<proto::swift::WirePointer<TypeParam>> SwiftMakeDummyInputSimdMatrices(
  PartyPointer& party, size_t m, size_t n, size_t number_of_simd_values) {
  auto backend = party->GetBackend();
  auto reg = backend->GetRegister();
  
  ublas::matrix<proto::swift::WirePointer<TypeParam>> result(m, n);
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      std::vector<TypeParam> simd_input1, simd_input2, simd_input3;
      simd_input1.reserve(number_of_simd_values);
      simd_input2.reserve(number_of_simd_values);
      simd_input3.reserve(number_of_simd_values);
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        simd_input1.emplace_back(42);
        simd_input2.emplace_back(42);
        simd_input3.emplace_back(42);
      }
      auto w = reg->template EmplaceWire<proto::swift::Wire<TypeParam>>(
        *backend, number_of_simd_values, std::move(simd_input1), std::move(simd_input2), std::move(simd_input3));
      result(i, j) = w;
      w->SetSetupIsReady();
      w->SetOnlineFinished();
    }
  }
  return result;
}

ublas::matrix<proto::socium::WirePointer<TypeParam>> SociumMakeDummyInputSimdMatrices(
  PartyPointer& party, size_t m, size_t n, size_t number_of_simd_values) {
  auto backend = party->GetBackend();
  auto reg = backend->GetRegister();
  
  ublas::matrix<proto::socium::WirePointer<TypeParam>> result(m, n);
  for(size_t i = 0; i != m; ++i) {
    for(size_t j = 0; j != n; ++j) {
      std::vector<TypeParam> simd_input1, simd_input2, simd_input3;
      simd_input1.reserve(number_of_simd_values);
      simd_input2.reserve(number_of_simd_values);
      simd_input3.reserve(number_of_simd_values);
      for(size_t s = 0; s != number_of_simd_values; ++s) {
        simd_input1.emplace_back(42);
        simd_input2.emplace_back(42);
        simd_input3.emplace_back(42);
      }
      auto w = reg->template EmplaceWire<proto::socium::Wire<TypeParam>>(
        *backend, number_of_simd_values, std::move(simd_input1), std::move(simd_input2), std::move(simd_input3));
      result(i, j) = w;
      w->SetSetupIsReady();
      w->SetOnlineFinished();
    }
  }
  return result;
}

void AssignSquare(ublas::matrix<ShareWrapper>& D, ublas::matrix<ShareWrapper> const& C_k, 
                  size_t window, size_t D_row_offset, size_t D_column_offset,
                  size_t C_row_offset, size_t C_column_offset) {
  for(size_t i = 0; i != window; ++i) {
    for(size_t j = 0; j != window; ++j) {
      D(D_row_offset + window*i + j, D_column_offset) = 
        C_k(C_row_offset + i, C_column_offset + j);
    }
  }
}

void AssignSquare(ublas::matrix<proto::swift::WirePointer<TypeParam>>& D, 
                  ublas::matrix<proto::swift::WirePointer<TypeParam>> const& C_k, 
                  size_t window, size_t D_row_offset, size_t D_column_offset,
                  size_t C_row_offset, size_t C_column_offset) {
  for(size_t i = 0; i != window; ++i) {
    for(size_t j = 0; j != window; ++j) {
      D(D_row_offset + window*i + j, D_column_offset) = 
        C_k(C_row_offset + i, C_column_offset + j);
    }
  }
}

void AssignSquare(ublas::matrix<proto::socium::WirePointer<TypeParam>>& D, 
                  ublas::matrix<proto::socium::WirePointer<TypeParam>> const& C_k, 
                  size_t window, size_t D_row_offset, size_t D_column_offset,
                  size_t C_row_offset, size_t C_column_offset) {
  for(size_t i = 0; i != window; ++i) {
    for(size_t j = 0; j != window; ++j) {
      D(D_row_offset + window*i + j, D_column_offset) = 
        C_k(C_row_offset + i, C_column_offset + j);
    }
  }
}

ublas::matrix<ShareWrapper> Conv(std::vector<ublas::matrix<ShareWrapper>> C_ks,
                                 ublas::matrix<ShareWrapper> K, size_t w) {
  size_t m = C_ks[0].size1();
  size_t n = C_ks[0].size2();
  size_t max_m = m - w + 1;
  size_t max_n = n - w + 1;
  ublas::matrix<ShareWrapper> D(w*w * C_ks.size(), max_m * max_n);
  size_t row_offset = 0;
  for(size_t k = 0; k != C_ks.size(); ++k) {
    auto& C_k = C_ks[k];
    for(size_t i = 0; i != max_m; ++i) {
      for(size_t j = 0; j != max_n; ++j) {
        AssignSquare(D, C_k, w, row_offset, max_n * i + j, i, j);
      }
    }
    row_offset += w*w;
  }
  return FixedPointMatrixMultiplication(K, D, 16);
}

ublas::matrix<proto::swift::WirePointer<TypeParam>>
FixedPointMatrixMultiplication(
  ublas::matrix<proto::swift::WirePointer<TypeParam>> A, 
  ublas::matrix<proto::swift::WirePointer<TypeParam>> B, 
  size_t) {
  
  Backend& backend = A(0, 0)->GetBackend();
  
  auto matrix_conversion_gate_A = 
    backend.GetRegister()->EmplaceGate<proto::swift::MatrixConversionGate<uint64_t>>(A);
  auto matrix_conversion_wire_A = 
    std::dynamic_pointer_cast<proto::swift::MatrixWire<uint64_t>>(
      matrix_conversion_gate_A->GetOutputWires()[0]);
      
  auto matrix_conversion_gate_B = 
    backend.GetRegister()->EmplaceGate<proto::swift::MatrixConversionGate<uint64_t>>(B);
  auto matrix_conversion_wire_B = 
    std::dynamic_pointer_cast<proto::swift::MatrixWire<uint64_t>>(
      matrix_conversion_gate_B->GetOutputWires()[0]);
      
  auto fpa_mult_gate = 
    backend.GetRegister()->EmplaceGate<proto::swift::FpaMatrixMultiplicationGate<uint64_t>>(
      matrix_conversion_wire_A, matrix_conversion_wire_B);
  auto fpa_mult_wire = 
    std::dynamic_pointer_cast<proto::swift::MatrixWire<uint64_t>>(
      fpa_mult_gate->GetOutputWires()[0]);
      
  auto matrix_reconversion_gate = 
    backend.GetRegister()->EmplaceGate<proto::swift::MatrixReconversionGate<uint64_t>>(
      fpa_mult_wire);
  return matrix_reconversion_gate->GetWireMatrix();
}

ublas::matrix<proto::swift::WirePointer<TypeParam>> Conv(
  std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks,
  ublas::matrix<proto::swift::WirePointer<TypeParam>> K, size_t w) {
  size_t m = C_ks[0].size1();
  size_t n = C_ks[0].size2();
  size_t max_m = m - w + 1;
  size_t max_n = n - w + 1;
  ublas::matrix<proto::swift::WirePointer<TypeParam>> D(
    w*w * C_ks.size(), max_m * max_n);
  size_t row_offset = 0;
  for(size_t k = 0; k != C_ks.size(); ++k) {
    auto& C_k = C_ks[k];
    for(size_t i = 0; i != max_m; ++i) {
      for(size_t j = 0; j != max_n; ++j) {
        AssignSquare(D, C_k, w, row_offset, max_n * i + j, i, j);
      }
    }
    row_offset += w*w;
  }
  
  return FixedPointMatrixMultiplication(K, D, 16);
}

ublas::matrix<proto::socium::WirePointer<TypeParam>>
SociumFixedPointMatrixMultiplication(
  ublas::matrix<proto::socium::WirePointer<TypeParam>> A, 
  ublas::matrix<proto::socium::WirePointer<TypeParam>> B, 
  size_t precision) {
  
  Backend& backend = A(0, 0)->GetBackend();
  
  auto matrix_conversion_gate_A = 
    backend.GetRegister()->EmplaceGate<proto::socium::MatrixConversionGate<uint64_t>>(A);
  auto matrix_conversion_wire_A = 
    std::dynamic_pointer_cast<proto::socium::MatrixWire<uint64_t>>(
      matrix_conversion_gate_A->GetOutputWires()[0]);
      
  auto matrix_conversion_gate_B = 
    backend.GetRegister()->EmplaceGate<proto::socium::MatrixConversionGate<uint64_t>>(B);
  auto matrix_conversion_wire_B = 
    std::dynamic_pointer_cast<proto::socium::MatrixWire<uint64_t>>(
      matrix_conversion_gate_B->GetOutputWires()[0]);
      
  auto fpa_mult_gate = 
    backend.GetRegister()->EmplaceGate<proto::socium::FpaMatrixMultiplicationGate<uint64_t>>( // Only change
      matrix_conversion_wire_A, matrix_conversion_wire_B, precision);
  auto fpa_mult_wire = 
    std::dynamic_pointer_cast<proto::socium::MatrixWire<uint64_t>>(
      fpa_mult_gate->GetOutputWires()[0]);
      
  auto matrix_reconversion_gate = 
    backend.GetRegister()->EmplaceGate<proto::socium::MatrixReconversionGate<uint64_t>>(
      fpa_mult_wire);
  return matrix_reconversion_gate->GetWireMatrix();
}

ublas::matrix<proto::socium::WirePointer<TypeParam>> SociumConv(
  std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks,
  ublas::matrix<proto::socium::WirePointer<TypeParam>> K, size_t w) {
  size_t m = C_ks[0].size1();
  size_t n = C_ks[0].size2();
  size_t max_m = m - w + 1;
  size_t max_n = n - w + 1;
  ublas::matrix<proto::socium::WirePointer<TypeParam>> D(
    w*w * C_ks.size(), max_m * max_n);
  size_t row_offset = 0;
  for(size_t k = 0; k != C_ks.size(); ++k) {
    auto& C_k = C_ks[k];
    for(size_t i = 0; i != max_m; ++i) {
      for(size_t j = 0; j != max_n; ++j) {
        AssignSquare(D, C_k, w, row_offset, max_n * i + j, i, j);
      }
    }
    row_offset += w*w;
  }
  
  return SociumFixedPointMatrixMultiplication(K, D, 16); // Only change
}

ShareWrapper GetSquareSum(ublas::matrix<ShareWrapper> const& P, size_t w, 
                          size_t P_row_offset, size_t P_column_offset) {
  ShareWrapper square_sum = P(P_row_offset, P_column_offset);
  for(size_t i = 0; i != w; ++i) {
    for(size_t j = 0; j != w; ++j) {
      //Skip the first iteration as we already assigned it to square_sum
      if(i == 0 && j == 0) continue;
      square_sum += P(P_row_offset + i, P_column_offset + j);
    }
  }
  return square_sum;
}

proto::swift::WirePointer<TypeParam> GetSquareSum(
  ublas::matrix<proto::swift::WirePointer<TypeParam>> const& P, size_t w, 
  size_t P_row_offset, size_t P_column_offset) {
  proto::swift::WirePointer<TypeParam> square_sum = P(P_row_offset, P_column_offset);
  Backend& backend = square_sum->GetBackend();
  for(size_t i = 0; i != w; ++i) {
    for(size_t j = 0; j != w; ++j) {
      //Skip the first iteration as we already assigned it to square_sum
      if(i == 0 && j == 0) continue;
      square_sum = std::dynamic_pointer_cast<proto::swift::Wire<uint64_t>>(
        backend.GetRegister()->EmplaceGate<proto::swift::AdditionGate<TypeParam>>(
         square_sum, P(P_row_offset + i, P_column_offset + j))->GetOutputWires()[0]);
    }
  }
  return square_sum;
}

proto::socium::WirePointer<TypeParam> GetSquareSum(
  ublas::matrix<proto::socium::WirePointer<TypeParam>> const& P, size_t w, 
  size_t P_row_offset, size_t P_column_offset) {
  proto::socium::WirePointer<TypeParam> square_sum = P(P_row_offset, P_column_offset);
  Backend& backend = square_sum->GetBackend();
  for(size_t i = 0; i != w; ++i) {
    for(size_t j = 0; j != w; ++j) {
      //Skip the first iteration as we already assigned it to square_sum
      if(i == 0 && j == 0) continue;
      square_sum = std::dynamic_pointer_cast<proto::socium::Wire<uint64_t>>(
        backend.GetRegister()->EmplaceGate<proto::socium::AdditionGate<TypeParam>>(
         square_sum, P(P_row_offset + i, P_column_offset + j))->GetOutputWires()[0]);
    }
  }
  return square_sum;
}

ublas::matrix<ShareWrapper> AvgPool(ublas::matrix<ShareWrapper> P,
                                    size_t w, unsigned precision) {
  constexpr size_t kMaxPrecision = sizeof(size_t) * CHAR_BIT - 1;
  unsigned scaling_w_inv = kMaxPrecision - precision;
  size_t w_inv = (size_t(1) << kMaxPrecision) / w;
  if(scaling_w_inv < precision) {
    w_inv <<= precision - scaling_w_inv;
  } else if(scaling_w_inv > precision) {
    w_inv >>= scaling_w_inv - precision;
  }
  size_t w_inv_square = (w_inv * w_inv) >> precision;
  
  size_t m = P.size1();
  size_t n = P.size2();
  ublas::matrix<ShareWrapper> S(m/w, n/w);
  for(size_t i = 0; i != m/w; ++i) {
    for(size_t j = 0; j != n/w; ++j) {
      S(i, j) = GetSquareSum(P, w, w*i, w*j);
    }
  }
  
  return FixedPointMatrixConstantMultiplication(w_inv_square, S, precision);
}

ublas::matrix<proto::swift::WirePointer<TypeParam>> AvgPool(
  ublas::matrix<proto::swift::WirePointer<TypeParam>> P, size_t w, unsigned precision) {
  constexpr size_t kMaxPrecision = sizeof(size_t) * CHAR_BIT - 1;
  unsigned scaling_w_inv = kMaxPrecision - precision;
  size_t w_inv = (size_t(1) << kMaxPrecision) / w;
  if(scaling_w_inv < precision) {
    w_inv <<= precision - scaling_w_inv;
  } else if(scaling_w_inv > precision) {
    w_inv >>= scaling_w_inv - precision;
  }
  size_t w_inv_square = (w_inv * w_inv) >> precision;
  
  size_t m = P.size1();
  size_t n = P.size2();
  ublas::matrix<proto::swift::WirePointer<TypeParam>> S(m/w, n/w);
  for(size_t i = 0; i != m/w; ++i) {
    for(size_t j = 0; j != n/w; ++j) {
      S(i, j) = GetSquareSum(P, w, w*i, w*j);
    }
  }
  
  Backend& backend = S(0, 0)->GetBackend();
  
  auto matrix_conversion_gate_S = 
    backend.GetRegister()->EmplaceGate<proto::swift::MatrixConversionGate<uint64_t>>(S);
  auto matrix_conversion_wire_S = 
    std::dynamic_pointer_cast<proto::swift::MatrixWire<uint64_t>>(
      matrix_conversion_gate_S->GetOutputWires()[0]);
      
  auto fpa_mult_const_gate = 
    backend.GetRegister()->EmplaceGate<proto::swift::FpaMatrixMultiplicationConstantGate<uint64_t>>(
      matrix_conversion_wire_S, w_inv_square);
  auto fpa_mult_const_wire = 
    std::dynamic_pointer_cast<proto::swift::MatrixWire<uint64_t>>(
      fpa_mult_const_gate->GetOutputWires()[0]);
      
  auto matrix_reconversion_gate = 
    backend.GetRegister()->EmplaceGate<proto::swift::MatrixReconversionGate<uint64_t>>(
      fpa_mult_const_wire);
  return matrix_reconversion_gate->GetWireMatrix();
}

ublas::matrix<proto::socium::WirePointer<TypeParam>> SociumAvgPool(
  ublas::matrix<proto::socium::WirePointer<TypeParam>> P, size_t w, unsigned precision) {
  constexpr size_t kMaxPrecision = sizeof(size_t) * CHAR_BIT - 1;
  unsigned scaling_w_inv = kMaxPrecision - precision;
  size_t w_inv = (size_t(1) << kMaxPrecision) / w;
  if(scaling_w_inv < precision) {
    w_inv <<= precision - scaling_w_inv;
  } else if(scaling_w_inv > precision) {
    w_inv >>= scaling_w_inv - precision;
  }
  size_t w_inv_square = (w_inv * w_inv) >> precision;
  
  size_t m = P.size1();
  size_t n = P.size2();
  ublas::matrix<proto::socium::WirePointer<TypeParam>> S(m/w, n/w);
  for(size_t i = 0; i != m/w; ++i) {
    for(size_t j = 0; j != n/w; ++j) {
      S(i, j) = GetSquareSum(P, w, w*i, w*j);
    }
  }
  
  Backend& backend = S(0, 0)->GetBackend();
  
  auto matrix_conversion_gate_S = 
    backend.GetRegister()->EmplaceGate<proto::socium::MatrixConversionGate<uint64_t>>(S);
  auto matrix_conversion_wire_S = 
    std::dynamic_pointer_cast<proto::socium::MatrixWire<uint64_t>>(
      matrix_conversion_gate_S->GetOutputWires()[0]);
      
  auto fpa_mult_const_gate = 
    backend.GetRegister()->EmplaceGate<proto::socium::FpaMatrixMultiplicationConstantGate<uint64_t>>(
      matrix_conversion_wire_S, w_inv_square, precision);
  auto fpa_mult_const_wire = 
    std::dynamic_pointer_cast<proto::socium::MatrixWire<uint64_t>>(
      fpa_mult_const_gate->GetOutputWires()[0]);
      
  auto matrix_reconversion_gate = 
    backend.GetRegister()->EmplaceGate<proto::socium::MatrixReconversionGate<uint64_t>>(
      fpa_mult_const_wire);
  return matrix_reconversion_gate->GetWireMatrix();
}

void Benchmark_Astra_MNIST_1(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto c_0 = AstraMakeDummyInputMatrix(party, 28, 28);
    auto K = AstraMakeDummyInputMatrix(party, 16, 25);
    auto result = Conv({c_0}, K, 5);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_1: Conv(28x28, 16x25, 1, 5) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_1: Conv(28x28, 16x25, 1, 5)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_MNIST_2(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 16, 576);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_2: ReLU(16x576) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_2: ReLU(16x576)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_MNIST_3(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AstraMakeDummyInputSimdMatrices(party, 24, 24, 16);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_3: Avg(24x24, ... (16 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_3: Avg(24x24, ... (16 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_MNIST_4(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(16);
    for(size_t i = 0; i != 16; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 12, 12));
    }
    auto K = AstraMakeDummyInputMatrix(party, 16, 400);
    auto result = Conv(C_ks, K, 5);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_4: Conv(16x16, ... (16 times), 16x400, 16, 5) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_4: Conv(16x16, ... (16 times), 16x400, 16, 5)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_MNIST_5(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 16, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_5: ReLU(16x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_5: ReLU(16x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_MNIST_6(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AstraMakeDummyInputSimdMatrices(party, 8, 8, 16);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_6: Avg(8x8, ... (16 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_6: Avg(8x8, ... (16 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_MNIST_7(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = AstraMakeDummyInputMatrix(party, 100, 256);
    auto b = AstraMakeDummyInputMatrix(party, 256, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_7: FPA Matrix prod(100x256, 256x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_7: FPA Matrix prod(100x256, 256x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_MNIST_8(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 100, 1);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_8: ReLU(100x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_8: ReLU(100x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_MNIST_9(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = AstraMakeDummyInputMatrix(party, 10, 100);
    auto b = AstraMakeDummyInputMatrix(party, 100, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_9: FPA Matrix prod(10x100, 100x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_MNIST_9: FPA Matrix prod(10x100, 100x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_1(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(3);
    for(size_t i = 0; i != 3; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = AstraMakeDummyInputMatrix(party, 64, 27);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_1: Conv(34x34, ... (3 times), 64x27, 3, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_1: Conv(34x34, ... (3 times), 64x27, 3, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_2(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 64, 1024);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_2: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_2: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_3(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = AstraMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_3: Conv(34x34, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_3: Conv(34x34, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_4(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 64, 1024);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_4: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_4: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_5(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AstraMakeDummyInputSimdMatrices(party, 32, 32, 64);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_5: Avg(32x32, ... (64 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_5: Avg(32x32, ... (64 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_6(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = AstraMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_6: Conv(18x18, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_6: Conv(18x18, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_7(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 64, 256);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_7: ReLU(64x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_7: ReLU(64x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_8(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = AstraMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_8: Conv(18x18, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_8: Conv(18x18, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_9(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 64, 256);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_9: ReLU(64x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_9: ReLU(64x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_10(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AstraMakeDummyInputSimdMatrices(party, 16, 16, 64);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_10: Avg(16x16, ... (64 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_10: Avg(16x16, ... (64 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_11(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = AstraMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_11: Conv(10x10, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_11: Conv(10x10, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_12(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 64, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_12: ReLU(64x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_12: ReLU(64x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_13(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 8, 8));
    }
    auto K = AstraMakeDummyInputMatrix(party, 64, 64);
    auto result = Conv(C_ks, K, 1);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_13: Conv(8x8, ... (64 times), 64x64, 64, 1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_13: Conv(8x8, ... (64 times), 64x64, 64, 1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_14(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 64, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_14: ReLU(64x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_14: ReLU(64x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_15(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 8, 8));
    }
    auto K = AstraMakeDummyInputMatrix(party, 16, 64);
    auto result = Conv(C_ks, K, 1);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_15: Conv(8x8, ... (64 times), 16x64, 64, 1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_15: Conv(8x8, ... (64 times), 16x64, 64, 1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_16(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 16, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_16: ReLU(16x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_16: ReLU(16x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_CIFAR_10_17(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = AstraMakeDummyInputMatrix(party, 10, 1024);
    auto b = AstraMakeDummyInputMatrix(party, 1024, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_17: FPA Matrix prod(10x1024, 1024x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_CIFAR_10_17: FPA Matrix prod(10x1024, 1024x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_1(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(3);
    for(size_t i = 0; i != 3; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = AstraMakeDummyInputMatrix(party, 64, 27);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_1: Conv(34x34, ... (3 times), 64x27, 3, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_1: Conv(34x34, ... (3 times), 64x27, 3, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_2(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 64, 1024);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_2: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_2: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_3(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = AstraMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_3: Conv(34x34, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_3: Conv(34x34, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_4(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 64, 1024);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_4: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_4: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_5(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AstraMakeDummyInputSimdMatrices(party, 32, 32, 64);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_5: Avg(32x32, ... (64 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_5: Avg(32x32, ... (64 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_6(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = AstraMakeDummyInputMatrix(party, 128, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_6: Conv(18x18, ... (64 times), 128x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_6: Conv(18x18, ... (64 times), 128x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_7(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 128, 256);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_7: ReLU(128x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_7: ReLU(128x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_8(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(128);
    for(size_t i = 0; i != 128; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = AstraMakeDummyInputMatrix(party, 128, 1152);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_8: Conv(18x18, ... (128 times), 128x1152, 128, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_8: Conv(18x18, ... (128 times), 128x1152, 128, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_9(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 128, 256);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_9: ReLU(128x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_9: ReLU(128x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_10(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AstraMakeDummyInputSimdMatrices(party, 16, 16, 128);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_10: Avg(16x16, ... (128 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_10: Avg(16x16, ... (128 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_11(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(128);
    for(size_t i = 0; i != 128; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = AstraMakeDummyInputMatrix(party, 256, 1152);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_11: Conv(10x10, ... (128 times), 256x1152, 128, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_11: Conv(10x10, ... (128 times), 256x1152, 128, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_12(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 256, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_12: ReLU(256x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_12: ReLU(256x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_13(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(256);
    for(size_t i = 0; i != 256; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = AstraMakeDummyInputMatrix(party, 256, 2304);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_13: Conv(10x10, ... (256 times), 256x2304, 256, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_13: Conv(10x10, ... (256 times), 256x2304, 256, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_14(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 256, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_14: ReLU(256x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_14: ReLU(256x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_15(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(256);
    for(size_t i = 0; i != 256; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = AstraMakeDummyInputMatrix(party, 256, 2304);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_15: Conv(10x10, ... (256 times), 256x2304, 256, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_15: Conv(10x10, ... (256 times), 256x2304, 256, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_16(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 256, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_16: ReLU(256x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_16: ReLU(256x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_17(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AstraMakeDummyInputSimdMatrices(party, 8, 8, 256);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_17: Avg(8x8, ... (256 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_17: Avg(8x8, ... (256 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_18(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(256);
    for(size_t i = 0; i != 256; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 6, 6));
    }
    auto K = AstraMakeDummyInputMatrix(party, 512, 2304);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_18: Conv(6x6, ... (256 times), 512x2304, 256, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_18: Conv(6x6, ... (256 times), 512x2304, 256, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_19(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 512, 16);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_19: ReLU(512x16) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_19: ReLU(512x16)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_20(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 6, 6));
    }
    auto K = AstraMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_20: Conv(6x6, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_20: Conv(6x6, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_21(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 512, 16);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_21: ReLU(512x16) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_21: ReLU(512x16)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_22(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 6, 6));
    }
    auto K = AstraMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_22: Conv(6x6, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_22: Conv(6x6, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_23(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 512, 16);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_23: ReLU(512x16) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_23: ReLU(512x16)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_24(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AstraMakeDummyInputSimdMatrices(party, 4, 4, 512);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_24: Avg(4x4, ... (512 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_24: Avg(4x4, ... (512 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_25(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 4, 4));
    }
    auto K = AstraMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_25: Conv(4x4, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_25: Conv(4x4, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_26(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 512, 4);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_26: ReLU(512x4) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_26: ReLU(512x4)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_27(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 4, 4));
    }
    auto K = AstraMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_27: Conv(4x4, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_27: Conv(4x4, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_28(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 512, 4);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_28: ReLU(512x4) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_28: ReLU(512x4)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_29(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(AstraMakeDummyInputMatrix(party, 4, 4));
    }
    auto K = AstraMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_29: Conv(4x4, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_29: Conv(4x4, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_30(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 512, 4);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_30: ReLU(512x4) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_30: ReLU(512x4)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_31(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AstraMakeDummyInputSimdMatrices(party, 2, 2, 512);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_31: Avg(2x2, ... (512 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_31: Avg(2x2, ... (512 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_32(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = AstraMakeDummyInputMatrix(party, 4096, 512);
    auto b = AstraMakeDummyInputMatrix(party, 512, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_32: FPA Matrix prod(4096x512, 512x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_32: FPA Matrix prod(4096x512, 512x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_33(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 4096, 1);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_33: ReLU(4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_33: ReLU(4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_34(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = AstraMakeDummyInputMatrix(party, 4096, 4096);
    auto b = AstraMakeDummyInputMatrix(party, 4096, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_34: FPA Matrix prod(4096x4096, 4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_34: FPA Matrix prod(4096x4096, 4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_35(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 4096, 1);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_35: ReLU(4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_35: ReLU(4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_36(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = AstraMakeDummyInputMatrix(party, 1000, 4096);
    auto b = AstraMakeDummyInputMatrix(party, 4096, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_36: FPA Matrix prod(1000x4096, 4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_36: FPA Matrix prod(1000x4096, 4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Astra_VGG16_37(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AstraMakeDummyInputMatrix(party, 1000, 1);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_37: ReLU(1000x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Astra_VGG16_37: ReLU(1000x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// End: Astra /////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Auxiliator /////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Benchmark_Auxiliator_MNIST_1(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto c_0 = AuxiliatorMakeDummyInputMatrix(party, 28, 28);
    auto K = AuxiliatorMakeDummyInputMatrix(party, 16, 25);
    auto result = Conv({c_0}, K, 5);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_1: Conv(28x28, 16x25, 1, 5) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_1: Conv(28x28, 16x25, 1, 5)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_MNIST_2(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 16, 576);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_2: ReLU(16x576) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_2: ReLU(16x576)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_MNIST_3(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AuxiliatorMakeDummyInputSimdMatrices(party, 24, 24, 16);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_3: Avg(24x24, ... (16 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_3: Avg(24x24, ... (16 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_MNIST_4(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(16);
    for(size_t i = 0; i != 16; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 12, 12));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 16, 400);
    auto result = Conv(C_ks, K, 5);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_4: Conv(16x16, ... (16 times), 16x400, 16, 5) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_4: Conv(16x16, ... (16 times), 16x400, 16, 5)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_MNIST_5(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 16, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_5: ReLU(16x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_5: ReLU(16x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_MNIST_6(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AuxiliatorMakeDummyInputSimdMatrices(party, 8, 8, 16);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_6: Avg(8x8, ... (16 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_6: Avg(8x8, ... (16 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_MNIST_7(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = AuxiliatorMakeDummyInputMatrix(party, 100, 256);
    auto b = AuxiliatorMakeDummyInputMatrix(party, 256, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_7: FPA Matrix prod(100x256, 256x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_7: FPA Matrix prod(100x256, 256x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_MNIST_8(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 100, 1);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_8: ReLU(100x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_8: ReLU(100x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_MNIST_9(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = AuxiliatorMakeDummyInputMatrix(party, 10, 100);
    auto b = AuxiliatorMakeDummyInputMatrix(party, 100, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_9: FPA Matrix prod(10x100, 100x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_MNIST_9: FPA Matrix prod(10x100, 100x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_1(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(3);
    for(size_t i = 0; i != 3; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 64, 27);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_1: Conv(34x34, ... (3 times), 64x27, 3, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_1: Conv(34x34, ... (3 times), 64x27, 3, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_2(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 64, 1024);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_2: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_2: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_3(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_3: Conv(34x34, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_3: Conv(34x34, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_4(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 64, 1024);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_4: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_4: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_5(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AuxiliatorMakeDummyInputSimdMatrices(party, 32, 32, 64);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_5: Avg(32x32, ... (64 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_5: Avg(32x32, ... (64 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_6(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_6: Conv(18x18, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_6: Conv(18x18, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_7(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 64, 256);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_7: ReLU(64x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_7: ReLU(64x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_8(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_8: Conv(18x18, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_8: Conv(18x18, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_9(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 64, 256);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_9: ReLU(64x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_9: ReLU(64x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_10(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AuxiliatorMakeDummyInputSimdMatrices(party, 16, 16, 64);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_10: Avg(16x16, ... (64 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_10: Avg(16x16, ... (64 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_11(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_11: Conv(10x10, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_11: Conv(10x10, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_12(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 64, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_12: ReLU(64x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_12: ReLU(64x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_13(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 8, 8));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 64, 64);
    auto result = Conv(C_ks, K, 1);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_13: Conv(8x8, ... (64 times), 64x64, 64, 1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_13: Conv(8x8, ... (64 times), 64x64, 64, 1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_14(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 64, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_14: ReLU(64x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_14: ReLU(64x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_15(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 8, 8));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 16, 64);
    auto result = Conv(C_ks, K, 1);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_15: Conv(8x8, ... (64 times), 16x64, 64, 1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_15: Conv(8x8, ... (64 times), 16x64, 64, 1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_16(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 16, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_16: ReLU(16x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_16: ReLU(16x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_CIFAR_10_17(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = AuxiliatorMakeDummyInputMatrix(party, 10, 1024);
    auto b = AuxiliatorMakeDummyInputMatrix(party, 1024, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_17: FPA Matrix prod(10x1024, 1024x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_CIFAR_10_17: FPA Matrix prod(10x1024, 1024x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_1(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(3);
    for(size_t i = 0; i != 3; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 64, 27);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_1: Conv(34x34, ... (3 times), 64x27, 3, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_1: Conv(34x34, ... (3 times), 64x27, 3, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_2(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 64, 1024);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_2: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_2: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_3(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_3: Conv(34x34, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_3: Conv(34x34, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_4(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 64, 1024);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_4: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_4: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_5(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AuxiliatorMakeDummyInputSimdMatrices(party, 32, 32, 64);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_5: Avg(32x32, ... (64 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_5: Avg(32x32, ... (64 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_6(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 128, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_6: Conv(18x18, ... (64 times), 128x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_6: Conv(18x18, ... (64 times), 128x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_7(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 128, 256);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_7: ReLU(128x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_7: ReLU(128x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_8(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(128);
    for(size_t i = 0; i != 128; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 128, 1152);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_8: Conv(18x18, ... (128 times), 128x1152, 128, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_8: Conv(18x18, ... (128 times), 128x1152, 128, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_9(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 128, 256);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_9: ReLU(128x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_9: ReLU(128x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_10(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AuxiliatorMakeDummyInputSimdMatrices(party, 16, 16, 128);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_10: Avg(16x16, ... (128 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_10: Avg(16x16, ... (128 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_11(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(128);
    for(size_t i = 0; i != 128; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 256, 1152);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_11: Conv(10x10, ... (128 times), 256x1152, 128, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_11: Conv(10x10, ... (128 times), 256x1152, 128, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_12(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 256, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_12: ReLU(256x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_12: ReLU(256x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_13(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(256);
    for(size_t i = 0; i != 256; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 256, 2304);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_13: Conv(10x10, ... (256 times), 256x2304, 256, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_13: Conv(10x10, ... (256 times), 256x2304, 256, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_14(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 256, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_14: ReLU(256x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_14: ReLU(256x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_15(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(256);
    for(size_t i = 0; i != 256; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 256, 2304);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_15: Conv(10x10, ... (256 times), 256x2304, 256, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_15: Conv(10x10, ... (256 times), 256x2304, 256, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_16(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 256, 64);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_16: ReLU(256x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_16: ReLU(256x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_17(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AuxiliatorMakeDummyInputSimdMatrices(party, 8, 8, 256);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_17: Avg(8x8, ... (256 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_17: Avg(8x8, ... (256 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_18(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(256);
    for(size_t i = 0; i != 256; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 6, 6));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 512, 2304);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_18: Conv(6x6, ... (256 times), 512x2304, 256, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_18: Conv(6x6, ... (256 times), 512x2304, 256, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_19(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 512, 16);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_19: ReLU(512x16) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_19: ReLU(512x16)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_20(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 6, 6));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_20: Conv(6x6, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_20: Conv(6x6, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_21(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 512, 16);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_21: ReLU(512x16) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_21: ReLU(512x16)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_22(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 6, 6));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_22: Conv(6x6, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_22: Conv(6x6, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_23(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 512, 16);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_23: ReLU(512x16) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_23: ReLU(512x16)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_24(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AuxiliatorMakeDummyInputSimdMatrices(party, 4, 4, 512);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_24: Avg(4x4, ... (512 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_24: Avg(4x4, ... (512 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_25(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 4, 4));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_25: Conv(4x4, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_25: Conv(4x4, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_26(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 512, 4);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_26: ReLU(512x4) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_26: ReLU(512x4)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_27(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 4, 4));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_27: Conv(4x4, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_27: Conv(4x4, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_28(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 512, 4);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_28: ReLU(512x4) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_28: ReLU(512x4)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_29(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<ShareWrapper>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(AuxiliatorMakeDummyInputMatrix(party, 4, 4));
    }
    auto K = AuxiliatorMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_29: Conv(4x4, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_29: Conv(4x4, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_30(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 512, 4);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_30: ReLU(512x4) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_30: ReLU(512x4)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_31(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = AuxiliatorMakeDummyInputSimdMatrices(party, 2, 2, 512);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_31: Avg(2x2, ... (512 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_31: Avg(2x2, ... (512 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_32(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = AuxiliatorMakeDummyInputMatrix(party, 4096, 512);
    auto b = AuxiliatorMakeDummyInputMatrix(party, 512, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_32: FPA Matrix prod(4096x512, 512x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_32: FPA Matrix prod(4096x512, 512x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_33(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 4096, 1);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_33: ReLU(4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_33: ReLU(4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_34(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = AuxiliatorMakeDummyInputMatrix(party, 4096, 4096);
    auto b = AuxiliatorMakeDummyInputMatrix(party, 4096, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_34: FPA Matrix prod(4096x4096, 4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_34: FPA Matrix prod(4096x4096, 4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_35(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 4096, 1);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_35: ReLU(4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_35: ReLU(4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_36(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = AuxiliatorMakeDummyInputMatrix(party, 1000, 4096);
    auto b = AuxiliatorMakeDummyInputMatrix(party, 4096, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_36: FPA Matrix prod(1000x4096, 4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_36: FPA Matrix prod(1000x4096, 4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Auxiliator_VGG16_37(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = AuxiliatorMakeDummyInputMatrix(party, 1000, 1);
    auto result = encrypto::motion::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_37: ReLU(1000x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Auxiliator_VGG16_37: ReLU(1000x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// End: Auxiliator ////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Benchmark_ELSA(auto& user_options, size_t c, size_t m, size_t number_of_repetitions) {
  using std::to_string;
  using namespace std::string_literals;
  constexpr size_t kBitlen = 32;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t r = 0; r != number_of_repetitions; ++r) {
    PartyPointer party{CreateParty(user_options)};
    boost::numeric::ublas::matrix<ShareWrapper>  vectors(1, c);
    std::vector<ShareWrapper> sum_vector;
    for(size_t i = 0; i != c; ++i) {
      std::vector<ShareWrapper> converted_vector;
      converted_vector.reserve(m);
      for(size_t j = 0; j != m; ++j) {
        std::vector<ShareWrapper> entry;
        entry.reserve(kBitlen);
        for(size_t k = 0; k != kBitlen; ++k) {
          entry.emplace_back(party->In<MpcProtocol::kBooleanAstra>(BitVector<>::SecureRandom(1), (i % 2) + 1));
        }
        ShareWrapper converted_entry = B2A(std::move(entry), 2*kBitlen);
        converted_vector.emplace_back(std::move(converted_entry));
      }
      ShareWrapper dot_product = DotProduct(converted_vector, converted_vector)/* - 
                                 party->In<MpcProtocol::kAstra>(uint64_t(42))*/;
      vectors(0, i) = std::move(dot_product);
      if(i == 0) {
        sum_vector = std::move(converted_vector);
      } else {
        for(size_t j = 0; j != m; ++j) {
          sum_vector[j] += converted_vector[j];
        }
      }
    }
    MatrixMsb(vectors).Out();
    for(auto& sum : sum_vector) {
      sum.Out();
    }
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_ELSA: c="s + to_string(c) + ", m="s + to_string(m) + " - Setup Only"s,
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_ELSA: c="s + to_string(c) + ", m="s + to_string(m),
    accumulated_statistics, accumulated_communication_statistics);
}

namespace encrypto::motion {

template<typename T>
class TripleSacrifice {
 public:
  struct Triple {
    Triple(T lambda_x, T lambda_y, T gamma_xy)
    : lambda_x{lambda_x}, lambda_y{lambda_y}, gamma_xy{gamma_xy} {}
    
    T lambda_x, lambda_y, gamma_xy;
  };
  
  TripleSacrifice(Backend& backend)
  : backend_{backend}, gate_id_{backend.GetRegister()->NextGateId()} {
    auto& communication_layer = backend_.GetCommunicationLayer();
    auto my_id = communication_layer.GetMyId();
    auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
    
  if (my_id == 1) {
    triple_future_p1_p2_ = message_manager.RegisterReceive(
        2, communication::MessageType::kAuxiliatorVerifier, gate_id_);
  } else if (my_id == 2) {
    triple_future_p0_ = message_manager.RegisterReceive(
        0, communication::MessageType::kAuxiliatorVerifier, gate_id_);
    triple_future_p1_p2_ = message_manager.RegisterReceive(
        1, communication::MessageType::kAuxiliatorVerifier, gate_id_);
  }
    
  }
  
  //The share triple of each party. As P0 has both lambda shares,
  //P0 should input (lambda_x1 + lambda_x2) etc.
  void AppendTriple(T const& lambda_x, T const& lambda_y, T const& gamma_xy) {
    triples_.emplace_back(lambda_x, lambda_y, gamma_xy);
  }
  
  bool CheckZero() {
    auto& communication_layer = backend_.GetCommunicationLayer();
    auto my_id = communication_layer.GetMyId();
    size_t number_of_triples = triples_.size();
    bool result = true;
    switch(my_id) {
      case 0: {
        auto& rng1 = backend_.GetBaseProvider().GetMyRandomnessGenerator(1);
        auto& rng2 = backend_.GetBaseProvider().GetMyRandomnessGenerator(2);
        //lambda1_x's are at [0,..., number_of_triples), 
        //gamma1_x'ys are at [number_of_triple,..., 2*number_of_triples)
        std::vector<T> randoms1 = rng1.template GetUnsigned<T>(gate_id_, 2*number_of_triples);
        //lambda2_x's are at [0,..., number_of_triples)
        std::vector<T> randoms2 = rng2.template GetUnsigned<T>(gate_id_, number_of_triples);
        for(size_t i = 0; i != number_of_triples; ++i) {
          T lambda_x_prime = randoms1[i] + randoms2[i];
          T lambda_y = triples_[i].lambda_y;
          T const& gamma1_x_prime_y = randoms1[number_of_triples + i];
          randoms2[i] = lambda_x_prime * lambda_y - gamma1_x_prime_y;
        }
        //Now randoms2 contain gamma2_x'ys
        auto payload = ToByteVector<T>(randoms2);
        auto message = communication::BuildMessage(communication::MessageType::kAuxiliatorVerifier,
                                               gate_id_, payload);
        communication_layer.SendMessage(2, message.Release());
        break;
      }
      case 1: {
        auto& rng0 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(0);
        auto& rng2 = backend_.GetBaseProvider().GetMyRandomnessGenerator(2);
        //lambda1_x's are at [0,..., number_of_triples), 
        //gamma1_x'ys are at [number_of_triple,..., 2*number_of_triples)
        std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, 2*number_of_triples);
        //Only one random value shared between P1 and P2 is enough for the protocol
        T r = rng2.template GetUnsigned<T>(gate_id_, 1)[0];

        std::vector<T> w;
        w.reserve(number_of_triples);
        for(size_t i = 0; i != number_of_triples; ++i) {
          T const& lambda1_x = triples_[i].lambda_x;
          T const& lambda1_x_prime = randoms0[i];
          w.emplace_back(r * lambda1_x - lambda1_x_prime);
        }
        assert(w.size() == number_of_triples);
        //v1s are in w now
        
        auto message = triple_future_p1_p2_.get();
        auto payload = communication::GetMessage(message.data())->payload();
        //v2s are in [0,..., number_of_triples)
        std::vector<T> values = FromByteVector<T>({payload->Data(), payload->size()});
        assert(values.size() == number_of_triples);
        //We have to send the v1s later and will overwrite w now, so we store a copy of its serialization
        auto serialized_data = ToByteVector<T>(w);
        
        for(size_t i = 0; i != number_of_triples; ++i) {
          T const& lambda1_y = triples_[i].lambda_y;
          T const& gamma1_xy = triples_[i].gamma_xy;
          T const& gamma1_x_prime_y = randoms0[number_of_triples + i];
          T v = w[i] + values[i];
          w[i] = v * lambda1_y - r * gamma1_xy + gamma1_x_prime_y;
        }
        //Now ws are in w
        
        std::vector<uint8_t> w1(EVP_MAX_MD_SIZE);
        Blake2b(reinterpret_cast<uint8_t*>(w.data()), w1.data(), w.size());
        serialized_data.insert(serialized_data.end(), w1.begin(), w1.end());
        auto send_message = communication::BuildMessage(communication::MessageType::kAuxiliatorVerifier,
                                                        gate_id_, serialized_data);
        communication_layer.SendMessage(2, send_message.Release());
        break;
      }
      case 2: {
        auto& rng0 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(0);
        auto& rng1 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(1);
        //lambda2_xs are in randoms0
        std::vector<T> randoms0 = rng0.template GetUnsigned<T>(gate_id_, number_of_triples);
        //Only one random value shared between P1 and P2 is enough for the protocol
        T r = rng1.template GetUnsigned<T>(gate_id_, 1)[0];

        std::vector<T> w;
        w.reserve(number_of_triples);
        for(size_t i = 0; i != number_of_triples; ++i) {
          T const& lambda2_x = triples_[i].lambda_x;
          T const& lambda2_x_prime = randoms0[i];
          w.emplace_back(r * lambda2_x - lambda2_x_prime);
        }
        assert(w.size() == number_of_triples);
        //v2s are in w now
        
        {
          auto payload = ToByteVector<T>(w);
          auto message = communication::BuildMessage(communication::MessageType::kAuxiliatorVerifier,
                                               gate_id_, payload);
          communication_layer.SendMessage(1, message.Release());
        }

        auto message = triple_future_p0_.get();
        auto payload = communication::GetMessage(message.data())->payload();
        std::vector<T> gamma2_x_prime_y_vector = FromByteVector<T>({payload->Data(), payload->size()});
        assert(gamma2_x_prime_y_vector.size() == number_of_triples);
        
        message = triple_future_p1_p2_.get();
        payload = communication::GetMessage(message.data())->payload();
        //v1s are in [0,..., number_of_triples)
        //w1 is in [number_of_triples,..., number_of_triples + EVP_MAX_MD_SIZE)
        std::vector<T> values = FromByteVector<T>({payload->Data(), payload->size()});
        assert(values.size() == number_of_triples + EVP_MAX_MD_SIZE / sizeof(T));
        
        for(size_t i = 0; i != number_of_triples; ++i) {
          T const& lambda2_y = triples_[i].lambda_y;
          T const& gamma2_xy = triples_[i].gamma_xy;
          T const& gamma2_x_prime_y = gamma2_x_prime_y_vector[i];
          T v = values[i] + w[i];
          w[i] = -(v * lambda2_y - r * gamma2_xy + gamma2_x_prime_y);
        }
        //Now ws are in w
        
        std::vector<uint8_t> w2(EVP_MAX_MD_SIZE);
        Blake2b(reinterpret_cast<uint8_t*>(w.data()), w2.data(), w.size());
        uint8_t* w1 = reinterpret_cast<uint8_t*>(values.data() + number_of_triples);
        for(size_t i = 0; i != EVP_MAX_MD_SIZE; ++i) {
          if(w2[i] != w1[i]) {
            result = false;
          }
        }
        break;
      }
    }
    return result;
  }
  
 private:
  std::vector<Triple> triples_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> triple_future_p0_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> triple_future_p1_p2_;
  Backend& backend_;
  size_t gate_id_;
};


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

template<typename T>
std::vector<uint8_t> SerializeMatrices(
  std::vector<boost::numeric::ublas::matrix<T>> const& matrices) {

  std::vector<uint8_t> result;
  size_t number_of_matrices = matrices.size();
  for(auto const& mat : matrices) {
    size_t u = mat.size1();
    size_t v = mat.size2();
    for(size_t i = 0; i != u; ++i) {
      for(size_t j = 0; j != v; ++j) {
        T tmp = mat(i, j);
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
  auto message_it = message.begin();
  for(auto& mat : matrices) {
    size_t u = mat.size1();
    size_t v = mat.size2();
    for(size_t i = 0; i != u; ++i) {
      for(size_t j = 0; j != v; ++j) {
        T tmp = 0;
        for(size_t b = 0; b != sizeof(T); ++b, ++message_it) {
          assert(message_it != message.end());
          tmp |= T(*message_it) << (b * CHAR_BIT);
        }
        mat(i, j) = tmp;
      }
    }
  }
  assert(message_it == message.end());
}

} // namespace (anonymous)

template<typename T>
class MatrixTripleSacrifice {
 public:
  struct Triple {
    Triple(boost::numeric::ublas::matrix<T> lambda_x, 
           boost::numeric::ublas::matrix<T> lambda_y, 
           boost::numeric::ublas::matrix<T> gamma_xy)
    : lambda_x{lambda_x}, lambda_y{lambda_y}, gamma_xy{gamma_xy} {}
    
    boost::numeric::ublas::matrix<T> lambda_x, lambda_y, gamma_xy;
  };
  
  MatrixTripleSacrifice(Backend& backend)
  : backend_{backend}, gate_id_{backend.GetRegister()->NextGateId()} {
    auto& communication_layer = backend_.GetCommunicationLayer();
    auto my_id = communication_layer.GetMyId();
    auto& message_manager = backend_.GetCommunicationLayer().GetMessageManager();
    
    if (my_id == 1) {
      triple_future_p1_p2_ = message_manager.RegisterReceive(
          2, communication::MessageType::kAuxiliatorVerifier, gate_id_);
    } else if (my_id == 2) {
      triple_future_p0_ = message_manager.RegisterReceive(
          0, communication::MessageType::kAuxiliatorVerifier, gate_id_);
      triple_future_p1_p2_ = message_manager.RegisterReceive(
          1, communication::MessageType::kAuxiliatorVerifier, gate_id_);
    }
    
  }
  
  std::vector<boost::numeric::ublas::matrix<T>> 
  GenerateLambdaXPrime(primitives::SharingRandomnessGenerator& rng) {
    size_t random_size = 0;
    size_t number_of_triples = triples_.size();
    std::vector<boost::numeric::ublas::matrix<T>> result;
    result.reserve(number_of_triples);
    for(Triple const& triple : triples_) {
      size_t u = triple.lambda_x.size1();
      size_t w = triple.lambda_x.size2();
      random_size += u * w;
      result.emplace_back(u, w);
    }
    
    auto data = rng.template GetUnsigned<T>(gate_id_, random_size);
    auto data_it = data.begin();
    for(size_t s = 0; s != number_of_triples; ++s) {
      size_t u = triples_[s].lambda_x.size1();
      size_t w = triples_[s].lambda_x.size2();
      for(size_t i = 0; i != u; ++i){
        for(size_t j = 0; j != w; ++j, ++data_it) {
          assert(data_it != data.end());
          result[s](i, j) = *data_it;
        }
      }
    }
    assert(data_it == data.end());
    return result;
  }
  
  std::vector<boost::numeric::ublas::matrix<T>> 
  GenerateLambdaXPrimeGammaXPrimeY(primitives::SharingRandomnessGenerator& rng) {
    size_t random_size = 0;
    size_t number_of_triples = triples_.size();
    std::vector<boost::numeric::ublas::matrix<T>> result(2*number_of_triples);
    for(size_t i = 0; i != number_of_triples; ++i) {
      size_t u = triples_[i].lambda_x.size1();
      size_t w = triples_[i].lambda_x.size2();
      size_t v = triples_[i].gamma_xy.size2();
      random_size += u * w + u * v;
      result[i].resize(u, w, false);
      result[i + number_of_triples].resize(u, v, false);
    }
    
    auto data = rng.template GetUnsigned<T>(gate_id_, random_size);
    auto data_it = data.begin();
    for(size_t s = 0; s != number_of_triples; ++s) {
      size_t u = triples_[s].lambda_x.size1();
      size_t w = triples_[s].lambda_x.size2();
      for(size_t i = 0; i != u; ++i){
        for(size_t j = 0; j != w; ++j, ++data_it) {
          assert(data_it != data.end());
          result[s](i, j) = *data_it;
        }
      }
    }
    for(size_t s = 0; s != number_of_triples; ++s) {
      size_t u = triples_[s].lambda_x.size1();
      size_t v = triples_[s].gamma_xy.size2();
      for(size_t i = 0; i != u; ++i){
        for(size_t j = 0; j != v; ++j, ++data_it) {
          assert(data_it != data.end());
          result[s + number_of_triples](i, j) = *data_it;
        }
      }
    }
    assert(data_it == data.end());
    return result;
  }
  
  //The share triple of each party. As P0 has both lambda shares,
  //P0 should input (lambda_x1 + lambda_x2) etc.
  void AppendTriple(boost::numeric::ublas::matrix<T> lambda_x, 
                    boost::numeric::ublas::matrix<T> lambda_y, 
                    boost::numeric::ublas::matrix<T> gamma_xy) {
    assert(lambda_x.size2() == lambda_y.size1());
    assert(lambda_x.size1() == gamma_xy.size1());
    assert(lambda_y.size2() == gamma_xy.size2());
    triples_.emplace_back(std::move(lambda_x), std::move(lambda_y), std::move(gamma_xy));
  }
  
  bool CheckZero() {
    using boost::numeric::ublas::matrix;
    auto& communication_layer = backend_.GetCommunicationLayer();
    auto my_id = communication_layer.GetMyId();
    size_t number_of_triples = triples_.size();
    bool result = true;
    
    switch(my_id) {
      case 0: {
        auto& rng1 = backend_.GetBaseProvider().GetMyRandomnessGenerator(1);
        auto& rng2 = backend_.GetBaseProvider().GetMyRandomnessGenerator(2);
        //lambda1_x's are at [0,..., number_of_triples), 
        //gamma1_x'ys are at [number_of_triple,..., 2*number_of_triples)
        auto randoms1 = GenerateLambdaXPrimeGammaXPrimeY(rng1);
        //lambda2_x's are at [0,..., number_of_triples)
        auto randoms2 = GenerateLambdaXPrime(rng2);
        for(size_t i = 0; i != number_of_triples; ++i) {
          auto const& lambda_y = triples_[i].lambda_y;
          auto const& gamma1_x_prime_y = randoms1[number_of_triples + i];
          randoms2[i] = prod(randoms1[i] + randoms2[i], lambda_y) - gamma1_x_prime_y;
        }
        //Now randoms2 contain gamma2_x'ys
        auto payload = SerializeMatrices(randoms2);
        auto send_message = communication::BuildMessage(communication::MessageType::kAuxiliatorVerifier,
                                                        gate_id_, payload);
        communication_layer.SendMessage(2, send_message.Release());
        break;
      }
      case 1: {
        auto& rng0 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(0);
        auto& rng2 = backend_.GetBaseProvider().GetMyRandomnessGenerator(2);
        //lambda1_x's are at [0,..., number_of_triples), 
        //gamma1_x'ys are at [number_of_triple,..., 2*number_of_triples)
        auto randoms0 = GenerateLambdaXPrimeGammaXPrimeY(rng0);
        //Only one random value shared between P1 and P2 is enough for the protocol
        T r = rng2.template GetUnsigned<T>(gate_id_, 1)[0];

        std::vector<matrix<T>> w;
        w.reserve(number_of_triples);
        for(size_t i = 0; i != number_of_triples; ++i) {
          auto const& lambda1_x = triples_[i].lambda_x;
          auto const& lambda1_x_prime = randoms0[i];
          w.emplace_back(r * lambda1_x - lambda1_x_prime);
        }
        assert(w.size() == number_of_triples);
        //v1s are in w now
        
        std::vector<matrix<T>> values;
        values.reserve(number_of_triples);
        [[maybe_unused]] size_t values_size_in_bytes = 0;
        for(auto const& triple : triples_) {
          size_t u = triple.lambda_x.size1();
          size_t w = triple.lambda_x.size2();
          values.emplace_back(u, w);
          assert( (values_size_in_bytes += sizeof(T) * u * w, true) );
        }
        assert(values.size() == number_of_triples);
        auto message = triple_future_p1_p2_.get();
        auto payload = communication::GetMessage(message.data())->payload();
        assert(payload->size() == values_size_in_bytes);
        //v2s are in [0,..., number_of_triples)
        DeserializeMatrices(values, {payload->Data(), payload->size()});
        //We have to send the v1s later and will overwrite w now, so we store a copy of its serialization
        auto serialized_data = SerializeMatrices(w);
        
        for(size_t i = 0; i != number_of_triples; ++i) {
          auto const& lambda1_y = triples_[i].lambda_y;
          auto const& gamma1_xy = triples_[i].gamma_xy;
          auto const& gamma1_x_prime_y = randoms0[number_of_triples + i];
          w[i] = prod(w[i] + values[i], lambda1_y) - r * gamma1_xy + gamma1_x_prime_y;
        }
        //Now ws are in w
        
        std::vector<uint8_t> w1(EVP_MAX_MD_SIZE);
        {
          auto tmp = SerializeMatrices(w);
          Blake2b(tmp.data(), w1.data(), tmp.size());
        }
        serialized_data.insert(serialized_data.end(), w1.begin(), w1.end());
        auto send_message = communication::BuildMessage(communication::MessageType::kAuxiliatorVerifier,
                                                        gate_id_, serialized_data);
        communication_layer.SendMessage(2, send_message.Release());
        break;
      }
      case 2: {
        auto& rng0 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(0);
        auto& rng1 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(1);
        //lambda2_x's are at [0,..., number_of_triples)
        auto randoms0 = GenerateLambdaXPrime(rng0);
        //Only one random value shared between P1 and P2 is enough for the protocol
        T r = rng1.template GetUnsigned<T>(gate_id_, 1)[0];

        std::vector<matrix<T>> w;
        w.reserve(number_of_triples);
        for(size_t i = 0; i != number_of_triples; ++i) {
          auto const& lambda2_x = triples_[i].lambda_x;
          auto const& lambda2_x_prime = randoms0[i];
          w.emplace_back(r * lambda2_x - lambda2_x_prime);
        }
        assert(w.size() == number_of_triples);
        //v2s are in w now
        
        {
          auto payload = SerializeMatrices(w);
          auto message = communication::BuildMessage(communication::MessageType::kAuxiliatorVerifier,
                                               gate_id_, payload);
          communication_layer.SendMessage(1, message.Release());
        }
        
        std::vector<matrix<T>> gamma2_x_prime_y_vector;
        gamma2_x_prime_y_vector.reserve(number_of_triples);
        [[maybe_unused]] size_t gamma2_x_prime_y_vector_size_in_bytes = 0;
        for(auto const& triple : triples_) {
          size_t u = triple.gamma_xy.size1();
          size_t v = triple.gamma_xy.size2();
          gamma2_x_prime_y_vector.emplace_back(u, v);
          assert( (gamma2_x_prime_y_vector_size_in_bytes += sizeof(T) * u * v, true) );
        }
        assert(gamma2_x_prime_y_vector.size() == number_of_triples);
        auto message = triple_future_p0_.get();
        auto payload = communication::GetMessage(message.data())->payload();
        assert(payload->size() == gamma2_x_prime_y_vector_size_in_bytes);
        DeserializeMatrices(gamma2_x_prime_y_vector, {payload->Data(), payload->size()});
        
        std::vector<matrix<T>> values;
        values.reserve(number_of_triples);
        size_t values_size_in_bytes = 0;
        for(auto const& triple : triples_) {
          size_t u = triple.lambda_x.size1();
          size_t w = triple.lambda_x.size2();
          values.emplace_back(u, w);
          values_size_in_bytes += sizeof(T) * u * w;
        }
        assert(values.size() == number_of_triples);
        message = triple_future_p1_p2_.get();
        payload = communication::GetMessage(message.data())->payload();
        assert(payload->size() == values_size_in_bytes + EVP_MAX_MD_SIZE);
        //v1s are in [0,..., number_of_triples)
        //w1 is in [number_of_triples,..., number_of_triples + EVP_MAX_MD_SIZE)
        DeserializeMatrices(values, {payload->Data(), values_size_in_bytes});
        
        for(size_t i = 0; i != number_of_triples; ++i) {
          auto const& lambda2_y = triples_[i].lambda_y;
          auto const& gamma2_xy = triples_[i].gamma_xy;
          auto const& gamma2_x_prime_y = gamma2_x_prime_y_vector[i];
          w[i] = -(prod(values[i] + w[i], lambda2_y) - r * gamma2_xy + gamma2_x_prime_y);
        }
        //Now ws are in w
        
        std::vector<uint8_t> w2(EVP_MAX_MD_SIZE);
        {
          auto tmp = SerializeMatrices(w);
          Blake2b(tmp.data(), w2.data(), tmp.size());
        }
        uint8_t const* w1 = payload->data() + number_of_triples * sizeof(T);
        for(size_t i = 0; i != EVP_MAX_MD_SIZE; ++i) {
          if(w2[i] != w1[i]) {
            result = false;
          }
        }
        break;
      }
    }
    
    return result;
  }
  
 private:
  std::vector<Triple> triples_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> triple_future_p0_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> triple_future_p1_p2_;
  Backend& backend_;
  size_t gate_id_;
};

} // namespace encrypto::motion

void Benchmark_TripleSacrifice64(auto& user_options, size_t number_of_repetitions) {
  using namespace std::chrono;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    TripleSacrifice<uint64_t> triple_sacrifice(*party->GetBackend());
    party->GetBackend()->GetBaseProvider().Setup();
    unsigned __int128 lambda_x = 42, lambda_y = 42, gamma_xy = 42;
    auto start = steady_clock::now();
    for(size_t i = 0; i != 1'000'000; ++i) {
      triple_sacrifice.AppendTriple(lambda_x, lambda_y, gamma_xy);
    }
    auto end = steady_clock::now();
    duration<double> diff = end - start;
    std::cout << "Triple Sacrifice 64 bit: Appending 1'000'000 triples took: " << double(diff.count() * 1'000) << " ms" << std::endl;
    start = steady_clock::now();
    triple_sacrifice.CheckZero();
    end = steady_clock::now();
    diff = end - start;
    std::cout << "Triple Sacrifice 64 bit: CheckZero of 1'000'000 triples took: " << double(diff.count() * 1'000) << " ms" << std::endl;
    auto transport_statistics = party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    size_t number_of_messages_sent = 0, number_of_bytes_sent = 0, 
           number_of_messages_received = 0, number_of_bytes_received = 0;
    for(auto& statistic : transport_statistics) {
      number_of_messages_sent += statistic.number_of_messages_sent;
      number_of_bytes_sent += statistic.number_of_bytes_sent;
      number_of_messages_received += statistic.number_of_messages_received;
      number_of_bytes_received += statistic.number_of_bytes_received;
    }
    std::cout << "Number of messages sent: " << number_of_messages_sent << std::endl;
    std::cout << "Number of bytes sent: " << number_of_bytes_sent << std::endl;
    std::cout << "Number of messages received: " << number_of_messages_received << std::endl;
    std::cout << "Number of bytes received: " << number_of_bytes_received << "\n" << std::endl;
  }
}

void Benchmark_TripleSacrifice128(auto& user_options, size_t number_of_repetitions) {
  using namespace std::chrono;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    TripleSacrifice<unsigned __int128> triple_sacrifice(*party->GetBackend());
    party->GetBackend()->GetBaseProvider().Setup();
    unsigned __int128 lambda_x = 42, lambda_y = 42, gamma_xy = 42;
    auto start = steady_clock::now();
    for(size_t i = 0; i != 1'000'000; ++i) {
      triple_sacrifice.AppendTriple(lambda_x, lambda_y, gamma_xy);
    }
    auto end = steady_clock::now();
    duration<double> diff = end - start;
    std::cout << "Triple Sacrifice 128 bit: Appending 1'000'000 triples took: " << double(diff.count() * 1'000) << " ms" << std::endl;
    start = steady_clock::now();
    triple_sacrifice.CheckZero();
    end = steady_clock::now();
    diff = end - start;
    std::cout << "Triple Sacrifice 128 bit: CheckZero of 1'000'000 triples took: " << double(diff.count() * 1'000) << " ms" << std::endl;
    auto transport_statistics = party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    size_t number_of_messages_sent = 0, number_of_bytes_sent = 0, 
           number_of_messages_received = 0, number_of_bytes_received = 0;
    for(auto& statistic : transport_statistics) {
      number_of_messages_sent += statistic.number_of_messages_sent;
      number_of_bytes_sent += statistic.number_of_bytes_sent;
      number_of_messages_received += statistic.number_of_messages_received;
      number_of_bytes_received += statistic.number_of_bytes_received;
    }
    std::cout << "Number of messages sent: " << number_of_messages_sent << std::endl;
    std::cout << "Number of bytes sent: " << number_of_bytes_sent << std::endl;
    std::cout << "Number of messages received: " << number_of_messages_received << std::endl;
    std::cout << "Number of bytes received: " << number_of_bytes_received << "\n" << std::endl;
  }
}

void Benchmark_TripleMatrixTripleSacrifice128(auto& user_options, size_t number_of_repetitions, size_t u, size_t w, size_t v, size_t number_of_triples) {
  using namespace std::chrono;
  using boost::numeric::ublas::matrix;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    MatrixTripleSacrifice<unsigned __int128> matrix_triple_sacrifice(*(party->GetBackend()));
    party->GetBackend()->GetBaseProvider().Setup();
    matrix<unsigned __int128> lambda_x(u, w);
    matrix<unsigned __int128> lambda_y(w, v); 
    matrix<unsigned __int128> gamma_xy(u, v);
    for(size_t i = 0; i != u; ++i) {
      for(size_t j = 0; j != w; ++j) {
        lambda_x(i, j) = 42;
      }
    }
    for(size_t i = 0; i != w; ++i) {
      for(size_t j = 0; j != v; ++j) {
        lambda_y(i, j) = 42;
      }
    }
    for(size_t i = 0; i != u; ++i) {
      for(size_t j = 0; j != v; ++j) {
        gamma_xy(i, j) = 42;
      }
    }
    auto start = steady_clock::now();
    for(size_t i = 0; i != number_of_triples; ++i) {
      matrix_triple_sacrifice.AppendTriple(lambda_x, lambda_y, gamma_xy);
    }
    auto end = steady_clock::now();
    duration<double> diff = end - start;
    std::cout << "Triple Matrix Sacrifice 128 bit: Appending " << number_of_triples <<  " matrix triples ("
              << u << "x" << w << ", " << w << "x" << v << ", " << u << "x" << v << ") took: " 
              << double(diff.count() * 1'000) << " ms" << std::endl;
    start = steady_clock::now();
    matrix_triple_sacrifice.CheckZero();
    end = steady_clock::now();
    diff = end - start;
    std::cout << "Triple Matrix Sacrifice 128 bit: CheckZero of the " << number_of_triples 
              <<  " matrix triples took: " << double(diff.count() * 1'000) << " ms" << std::endl;
    auto transport_statistics = party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    size_t number_of_messages_sent = 0, number_of_bytes_sent = 0, 
           number_of_messages_received = 0, number_of_bytes_received = 0;
    for(auto& statistic : transport_statistics) {
      number_of_messages_sent += statistic.number_of_messages_sent;
      number_of_bytes_sent += statistic.number_of_bytes_sent;
      number_of_messages_received += statistic.number_of_messages_received;
      number_of_bytes_received += statistic.number_of_bytes_received;
    }
    std::cout << "Number of messages sent: " << number_of_messages_sent << std::endl;
    std::cout << "Number of bytes sent: " << number_of_bytes_sent << std::endl;
    std::cout << "Number of messages received: " << number_of_messages_received << std::endl;
    std::cout << "Number of bytes received: " << number_of_bytes_received << "\n" << std::endl;
  }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Swift //////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Benchmark_Swift_MNIST_1(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto c_0 = SwiftMakeDummyInputMatrix(party, 28, 28);
    auto K = SwiftMakeDummyInputMatrix(party, 16, 25);
    auto result = Conv({c_0}, K, 5);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_1: Conv(28x28, 16x25, 1, 5) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_1: Conv(28x28, 16x25, 1, 5)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_MNIST_2(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 16, 576);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_2: ReLU(16x576) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_2: ReLU(16x576)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_MNIST_3(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SwiftMakeDummyInputSimdMatrices(party, 24, 24, 16);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_3: Avg(24x24, ... (16 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_3: Avg(24x24, ... (16 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_MNIST_4(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(16);
    for(size_t i = 0; i != 16; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 12, 12));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 16, 400);
    auto result = Conv(C_ks, K, 5);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_4: Conv(16x16, ... (16 times), 16x400, 16, 5) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_4: Conv(16x16, ... (16 times), 16x400, 16, 5)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_MNIST_5(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 16, 64);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_5: ReLU(16x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_5: ReLU(16x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_MNIST_6(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SwiftMakeDummyInputSimdMatrices(party, 8, 8, 16);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_6: Avg(8x8, ... (16 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_6: Avg(8x8, ... (16 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_MNIST_7(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = SwiftMakeDummyInputMatrix(party, 100, 256);
    auto b = SwiftMakeDummyInputMatrix(party, 256, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_7: FPA Matrix prod(100x256, 256x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_7: FPA Matrix prod(100x256, 256x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_MNIST_8(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 100, 1);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_8: ReLU(100x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_8: ReLU(100x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_MNIST_9(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = SwiftMakeDummyInputMatrix(party, 10, 100);
    auto b = SwiftMakeDummyInputMatrix(party, 100, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_9: FPA Matrix prod(10x100, 100x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_MNIST_9: FPA Matrix prod(10x100, 100x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_1(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(3);
    for(size_t i = 0; i != 3; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 64, 27);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_1: Conv(34x34, ... (3 times), 64x27, 3, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_1: Conv(34x34, ... (3 times), 64x27, 3, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_2(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 64, 1024);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_2: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_2: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_3(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_3: Conv(34x34, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_3: Conv(34x34, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_4(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 64, 1024);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_4: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_4: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_5(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SwiftMakeDummyInputSimdMatrices(party, 32, 32, 64);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_5: Avg(32x32, ... (64 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_5: Avg(32x32, ... (64 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_6(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_6: Conv(18x18, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_6: Conv(18x18, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_7(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 64, 256);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_7: ReLU(64x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_7: ReLU(64x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_8(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_8: Conv(18x18, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_8: Conv(18x18, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_9(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 64, 256);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_9: ReLU(64x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_9: ReLU(64x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_10(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SwiftMakeDummyInputSimdMatrices(party, 16, 16, 64);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_10: Avg(16x16, ... (64 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_10: Avg(16x16, ... (64 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_11(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_11: Conv(10x10, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_11: Conv(10x10, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_12(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 64, 64);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_12: ReLU(64x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_12: ReLU(64x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_13(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 8, 8));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 64, 64);
    auto result = Conv(C_ks, K, 1);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_13: Conv(8x8, ... (64 times), 64x64, 64, 1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_13: Conv(8x8, ... (64 times), 64x64, 64, 1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_14(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 64, 64);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_14: ReLU(64x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_14: ReLU(64x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_15(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 8, 8));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 16, 64);
    auto result = Conv(C_ks, K, 1);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_15: Conv(8x8, ... (64 times), 16x64, 64, 1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_15: Conv(8x8, ... (64 times), 16x64, 64, 1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_16(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 16, 64);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_16: ReLU(16x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_16: ReLU(16x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_CIFAR_10_17(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = SwiftMakeDummyInputMatrix(party, 10, 1024);
    auto b = SwiftMakeDummyInputMatrix(party, 1024, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_17: FPA Matrix prod(10x1024, 1024x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_SWIFT_CIFAR_10_17: FPA Matrix prod(10x1024, 1024x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_1(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(3);
    for(size_t i = 0; i != 3; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 64, 27);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_1: Conv(34x34, ... (3 times), 64x27, 3, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_1: Conv(34x34, ... (3 times), 64x27, 3, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_2(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 64, 1024);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_2: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_2: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_3(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 64, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_3: Conv(34x34, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_3: Conv(34x34, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_4(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 64, 1024);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_4: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_4: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_5(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SwiftMakeDummyInputSimdMatrices(party, 32, 32, 64);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_5: Avg(32x32, ... (64 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_5: Avg(32x32, ... (64 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_6(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 128, 576);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_6: Conv(18x18, ... (64 times), 128x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_6: Conv(18x18, ... (64 times), 128x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_7(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 128, 256);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_7: ReLU(128x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_7: ReLU(128x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_8(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(128);
    for(size_t i = 0; i != 128; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 128, 1152);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_8: Conv(18x18, ... (128 times), 128x1152, 128, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_8: Conv(18x18, ... (128 times), 128x1152, 128, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_9(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 128, 256);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_9: ReLU(128x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_9: ReLU(128x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_10(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SwiftMakeDummyInputSimdMatrices(party, 16, 16, 128);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_10: Avg(16x16, ... (128 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_10: Avg(16x16, ... (128 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_11(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(128);
    for(size_t i = 0; i != 128; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 256, 1152);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_11: Conv(10x10, ... (128 times), 256x1152, 128, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_11: Conv(10x10, ... (128 times), 256x1152, 128, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_12(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 256, 64);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_12: ReLU(256x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_12: ReLU(256x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_13(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(256);
    for(size_t i = 0; i != 256; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 256, 2304);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_13: Conv(10x10, ... (256 times), 256x2304, 256, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_13: Conv(10x10, ... (256 times), 256x2304, 256, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_14(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 256, 64);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_14: ReLU(256x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_14: ReLU(256x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_15(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(256);
    for(size_t i = 0; i != 256; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 256, 2304);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_15: Conv(10x10, ... (256 times), 256x2304, 256, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_15: Conv(10x10, ... (256 times), 256x2304, 256, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_16(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 256, 64);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_16: ReLU(256x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_16: ReLU(256x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_17(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SwiftMakeDummyInputSimdMatrices(party, 8, 8, 256);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_17: Avg(8x8, ... (256 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_17: Avg(8x8, ... (256 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_18(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(256);
    for(size_t i = 0; i != 256; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 6, 6));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 512, 2304);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_18: Conv(6x6, ... (256 times), 512x2304, 256, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_18: Conv(6x6, ... (256 times), 512x2304, 256, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_19(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 512, 16);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_19: ReLU(512x16) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_19: ReLU(512x16)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_20(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 6, 6));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_20: Conv(6x6, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_20: Conv(6x6, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_21(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 512, 16);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_21: ReLU(512x16) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_21: ReLU(512x16)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_22(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 6, 6));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_22: Conv(6x6, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_22: Conv(6x6, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_23(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 512, 16);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_23: ReLU(512x16) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_23: ReLU(512x16)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_24(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SwiftMakeDummyInputSimdMatrices(party, 4, 4, 512);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_24: Avg(4x4, ... (512 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_24: Avg(4x4, ... (512 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_25(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 4, 4));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_25: Conv(4x4, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_25: Conv(4x4, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_26(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 512, 4);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_26: ReLU(512x4) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_26: ReLU(512x4)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_27(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 4, 4));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_27: Conv(4x4, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_27: Conv(4x4, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_28(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 512, 4);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_28: ReLU(512x4) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_28: ReLU(512x4)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_29(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::swift::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(SwiftMakeDummyInputMatrix(party, 4, 4));
    }
    auto K = SwiftMakeDummyInputMatrix(party, 512, 4608);
    auto result = Conv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_29: Conv(4x4, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_29: Conv(4x4, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_30(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 512, 4);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_30: ReLU(512x4) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_30: ReLU(512x4)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_31(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SwiftMakeDummyInputSimdMatrices(party, 2, 2, 512);
    auto result = AvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_31: Avg(2x2, ... (512 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_31: Avg(2x2, ... (512 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_32(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = SwiftMakeDummyInputMatrix(party, 4096, 512);
    auto b = SwiftMakeDummyInputMatrix(party, 512, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_32: FPA Matrix prod(4096x512, 512x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_32: FPA Matrix prod(4096x512, 512x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_33(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 4096, 1);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_33: ReLU(4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_33: ReLU(4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_34(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = SwiftMakeDummyInputMatrix(party, 4096, 4096);
    auto b = SwiftMakeDummyInputMatrix(party, 4096, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_34: FPA Matrix prod(4096x4096, 4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_34: FPA Matrix prod(4096x4096, 4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_35(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 4096, 1);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_35: ReLU(4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_35: ReLU(4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_36(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = SwiftMakeDummyInputMatrix(party, 1000, 4096);
    auto b = SwiftMakeDummyInputMatrix(party, 4096, 1);
    auto result = FixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_36: FPA Matrix prod(1000x4096, 4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_36: FPA Matrix prod(1000x4096, 4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Swift_VGG16_37(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SwiftMakeDummyInputMatrix(party, 1000, 1);
    auto result = proto::swift::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_37: ReLU(1000x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Swift_VGG16_37: ReLU(1000x1)",
    accumulated_statistics, accumulated_communication_statistics);
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// End: Swift /////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Socium (Malicious Evaluator) ///////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Benchmark_Socium_MNIST_1(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto c_0 = SociumMakeDummyInputMatrix(party, 28, 28);
    auto K = SociumMakeDummyInputMatrix(party, 16, 25);
    auto result = SociumConv({c_0}, K, 5);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_1: Conv(28x28, 16x25, 1, 5) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_1: Conv(28x28, 16x25, 1, 5)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_MNIST_2(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 16, 576);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_2: ReLU(16x576) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_2: ReLU(16x576)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_MNIST_3(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SociumMakeDummyInputSimdMatrices(party, 24, 24, 16);
    auto result = SociumAvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_3: Avg(24x24, ... (16 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_3: Avg(24x24, ... (16 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_MNIST_4(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(16);
    for(size_t i = 0; i != 16; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 12, 12));
    }
    auto K = SociumMakeDummyInputMatrix(party, 16, 400);
    auto result = SociumConv(C_ks, K, 5);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_4: Conv(16x16, ... (16 times), 16x400, 16, 5) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_4: Conv(16x16, ... (16 times), 16x400, 16, 5)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_MNIST_5(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 16, 64);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_5: ReLU(16x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_5: ReLU(16x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_MNIST_6(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SociumMakeDummyInputSimdMatrices(party, 8, 8, 16);
    auto result = SociumAvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_6: Avg(8x8, ... (16 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_6: Avg(8x8, ... (16 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_MNIST_7(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = SociumMakeDummyInputMatrix(party, 100, 256);
    auto b = SociumMakeDummyInputMatrix(party, 256, 1);
    auto result = SociumFixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_7: FPA Matrix prod(100x256, 256x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_7: FPA Matrix prod(100x256, 256x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_MNIST_8(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 100, 1);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_8: ReLU(100x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_8: ReLU(100x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_MNIST_9(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = SociumMakeDummyInputMatrix(party, 10, 100);
    auto b = SociumMakeDummyInputMatrix(party, 100, 1);
    auto result = SociumFixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_9: FPA Matrix prod(10x100, 100x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_MNIST_9: FPA Matrix prod(10x100, 100x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_1(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(3);
    for(size_t i = 0; i != 3; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = SociumMakeDummyInputMatrix(party, 64, 27);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_1: Conv(34x34, ... (3 times), 64x27, 3, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_1: Conv(34x34, ... (3 times), 64x27, 3, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_2(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 64, 1024);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_2: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_2: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_3(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = SociumMakeDummyInputMatrix(party, 64, 576);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_3: Conv(34x34, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_3: Conv(34x34, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_4(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 64, 1024);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_4: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_4: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_5(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SociumMakeDummyInputSimdMatrices(party, 32, 32, 64);
    auto result = SociumAvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_5: Avg(32x32, ... (64 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_5: Avg(32x32, ... (64 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_6(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = SociumMakeDummyInputMatrix(party, 64, 576);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_6: Conv(18x18, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_6: Conv(18x18, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_7(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 64, 256);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_7: ReLU(64x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_7: ReLU(64x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_8(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = SociumMakeDummyInputMatrix(party, 64, 576);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_8: Conv(18x18, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_8: Conv(18x18, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_9(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 64, 256);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_9: ReLU(64x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_9: ReLU(64x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_10(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SociumMakeDummyInputSimdMatrices(party, 16, 16, 64);
    auto result = SociumAvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_10: Avg(16x16, ... (64 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_10: Avg(16x16, ... (64 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_11(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = SociumMakeDummyInputMatrix(party, 64, 576);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_11: Conv(10x10, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_11: Conv(10x10, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_12(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 64, 64);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_12: ReLU(64x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_12: ReLU(64x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_13(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 8, 8));
    }
    auto K = SociumMakeDummyInputMatrix(party, 64, 64);
    auto result = SociumConv(C_ks, K, 1);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_13: Conv(8x8, ... (64 times), 64x64, 64, 1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_13: Conv(8x8, ... (64 times), 64x64, 64, 1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_14(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 64, 64);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_14: ReLU(64x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_14: ReLU(64x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_15(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 8, 8));
    }
    auto K = SociumMakeDummyInputMatrix(party, 16, 64);
    auto result = SociumConv(C_ks, K, 1);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_15: Conv(8x8, ... (64 times), 16x64, 64, 1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_15: Conv(8x8, ... (64 times), 16x64, 64, 1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_16(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 16, 64);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_16: ReLU(16x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_16: ReLU(16x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_CIFAR_10_17(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = SociumMakeDummyInputMatrix(party, 10, 1024);
    auto b = SociumMakeDummyInputMatrix(party, 1024, 1);
    auto result = SociumFixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_17: FPA Matrix prod(10x1024, 1024x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_CIFAR_10_17: FPA Matrix prod(10x1024, 1024x1)",
    accumulated_statistics, accumulated_communication_statistics);
}


void Benchmark_Socium_VGG16_1(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(3);
    for(size_t i = 0; i != 3; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = SociumMakeDummyInputMatrix(party, 64, 27);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_1: Conv(34x34, ... (3 times), 64x27, 3, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_1: Conv(34x34, ... (3 times), 64x27, 3, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_2(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 64, 1024);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_2: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_2: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_3(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 34, 34));
    }
    auto K = SociumMakeDummyInputMatrix(party, 64, 576);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_3: Conv(34x34, ... (64 times), 64x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_3: Conv(34x34, ... (64 times), 64x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_4(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 64, 1024);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_4: ReLU(64x1024) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_4: ReLU(64x1024)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_5(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SociumMakeDummyInputSimdMatrices(party, 32, 32, 64);
    auto result = SociumAvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_5: Avg(32x32, ... (64 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_5: Avg(32x32, ... (64 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_6(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(64);
    for(size_t i = 0; i != 64; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = SociumMakeDummyInputMatrix(party, 128, 576);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_6: Conv(18x18, ... (64 times), 128x576, 64, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_6: Conv(18x18, ... (64 times), 128x576, 64, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_7(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 128, 256);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_7: ReLU(128x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_7: ReLU(128x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_8(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(128);
    for(size_t i = 0; i != 128; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 18, 18));
    }
    auto K = SociumMakeDummyInputMatrix(party, 128, 1152);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_8: Conv(18x18, ... (128 times), 128x1152, 128, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_8: Conv(18x18, ... (128 times), 128x1152, 128, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_9(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 128, 256);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_9: ReLU(128x256) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_9: ReLU(128x256)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_10(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SociumMakeDummyInputSimdMatrices(party, 16, 16, 128);
    auto result = SociumAvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_10: Avg(16x16, ... (128 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_10: Avg(16x16, ... (128 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_11(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(128);
    for(size_t i = 0; i != 128; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = SociumMakeDummyInputMatrix(party, 256, 1152);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_11: Conv(10x10, ... (128 times), 64x576, 128, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_11: Conv(10x10, ... (128 times), 64x576, 128, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_12(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 256, 64);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_12: ReLU(256x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_12: ReLU(256x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_13(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(256);
    for(size_t i = 0; i != 256; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = SociumMakeDummyInputMatrix(party, 256, 2304);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_13: Conv(10x10, ... (256 times), 256x2304, 256, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_13: Conv(10x10, ... (256 times), 256x2304, 256, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_14(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 256, 64);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_14: ReLU(256x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_14: ReLU(256x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_15(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(256);
    for(size_t i = 0; i != 256; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 10, 10));
    }
    auto K = SociumMakeDummyInputMatrix(party, 256, 2304);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_15: Conv(10x10, ... (256 times), 256x2304, 256, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_15: Conv(10x10, ... (256 times), 256x2304, 256, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_16(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 256, 64);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_16: ReLU(256x64) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_16: ReLU(256x64)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_17(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SociumMakeDummyInputSimdMatrices(party, 8, 8, 256);
    auto result = SociumAvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_17: Avg(8x8, ... (256 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_17: Avg(8x8, ... (256 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_18(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(256);
    for(size_t i = 0; i != 256; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 6, 6));
    }
    auto K = SociumMakeDummyInputMatrix(party, 512, 2304);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_18: Conv(6x6, ... (256 times), 512x2304, 256, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_18: Conv(6x6, ... (256 times), 512x2304, 256, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_19(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 512, 16);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_19: ReLU(512x16) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_19: ReLU(512x16)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_20(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 6, 6));
    }
    auto K = SociumMakeDummyInputMatrix(party, 512, 4608);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_20: Conv(6x6, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_20: Conv(6x6, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_21(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 512, 16);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_21: ReLU(512x16) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_21: ReLU(512x16)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_22(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 6, 6));
    }
    auto K = SociumMakeDummyInputMatrix(party, 512, 4608);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_22: Conv(6x6, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_22: Conv(6x6, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_23(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 512, 16);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_23: ReLU(512x16) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_23: ReLU(512x16)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_24(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SociumMakeDummyInputSimdMatrices(party, 4, 4, 512);
    auto result = SociumAvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_24: Avg(4x4, ... (512 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_24: Avg(4x4, ... (512 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_25(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 4, 4));
    }
    auto K = SociumMakeDummyInputMatrix(party, 512, 4608);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_25: Conv(4x4, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_25: Conv(4x4, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_26(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 512, 4);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_26: ReLU(512x4) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_26: ReLU(512x4)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_27(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 4, 4));
    }
    auto K = SociumMakeDummyInputMatrix(party, 512, 4608);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_27: Conv(4x4, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_27: Conv(4x4, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_28(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 512, 4);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_28: ReLU(512x4) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_28: ReLU(512x4)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_29(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    std::vector<ublas::matrix<proto::socium::WirePointer<TypeParam>>> C_ks;
    C_ks.reserve(512);
    for(size_t i = 0; i != 512; ++i) {
      C_ks.emplace_back(SociumMakeDummyInputMatrix(party, 4, 4));
    }
    auto K = SociumMakeDummyInputMatrix(party, 512, 4608);
    auto result = SociumConv(C_ks, K, 3);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_29: Conv(4x4, ... (512 times), 512x4608, 512, 3) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_29: Conv(4x4, ... (512 times), 512x4608, 512, 3)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_30(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 512, 4);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_30: ReLU(512x4) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_30: ReLU(512x4)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_31(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto S = SociumMakeDummyInputSimdMatrices(party, 2, 2, 512);
    auto result = SociumAvgPool(S, 2, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_31: Avg(2x2, ... (512 times in parallel), 2) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_31: Avg(2x2, ... (512 times in parallel), 2)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_32(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = SociumMakeDummyInputMatrix(party, 4096, 512);
    auto b = SociumMakeDummyInputMatrix(party, 512, 1);
    auto result = SociumFixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_32: FPA Matrix prod(4096x512, 512x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_32: FPA Matrix prod(4096x512, 512x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_33(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 4096, 1);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_33: ReLU(4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_33: ReLU(4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_34(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = SociumMakeDummyInputMatrix(party, 4096, 4096);
    auto b = SociumMakeDummyInputMatrix(party, 4096, 1);
    auto result = SociumFixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_34: FPA Matrix prod(4096x4096, 4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_34: FPA Matrix prod(4096x4096, 4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_35(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 4096, 1);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_35: ReLU(4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_35: ReLU(4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_36(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto a = SociumMakeDummyInputMatrix(party, 1000, 4096);
    auto b = SociumMakeDummyInputMatrix(party, 4096, 1);
    auto result = SociumFixedPointMatrixMultiplication(a, b, 16);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_36: FPA Matrix prod(1000x4096, 4096x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
    
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_36: FPA Matrix prod(1000x4096, 4096x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

void Benchmark_Socium_VGG16_37(program_options::variables_map& user_options, size_t number_of_repetitions) {
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_setup_statistics;
  encrypto::motion::AccumulatedRunTimeStatistics accumulated_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_setup_communication_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;
  for (std::size_t i = 0; i != number_of_repetitions; ++i) {
    PartyPointer party{CreateParty(user_options)};
    auto m = SociumMakeDummyInputMatrix(party, 1000, 1);
    auto result = proto::socium::ReLU(m);
    party->Run();
    accumulated_setup_statistics.Add(g_setup_statistics);
    auto statistics = party->GetBackend()->GetRunTimeStatistics().front();
    accumulated_statistics.Add(statistics);
    accumulated_setup_communication_statistics.Add(g_setup_transport_statistics);
    auto communication_statistics =
      party->GetBackend()->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);
  }
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_37: ReLU(1000x1) - Setup Only",
    accumulated_setup_statistics, accumulated_setup_communication_statistics);
  std::cout << encrypto::motion::PrintStatistics(
    "Benchmark_Socium_VGG16_37: ReLU(1000x1)",
    accumulated_statistics, accumulated_communication_statistics);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// End: Socium (Malicious Evaluator) //////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const std::regex kPartyArgumentRegex(
    "(\\d+),(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}),(\\d{1,5})");

bool CheckPartyArgumentSyntax(const std::string& party_argument) {
  // other party's id, IP address, and port
  return std::regex_match(party_argument, kPartyArgumentRegex);
}

std::tuple<std::size_t, std::string, std::uint16_t> ParsePartyArgument(
    const std::string& party_argument) {
  std::smatch match;
  std::regex_match(party_argument, match, kPartyArgumentRegex);
  auto id = boost::lexical_cast<std::size_t>(match[1]);
  auto host = match[2];
  auto port = boost::lexical_cast<std::uint16_t>(match[3]);
  return {id, host, port};
}

// <variables map, help flag>
std::pair<program_options::variables_map, bool> ParseProgramOptions(int ac, char* av[]) {
  using namespace std::string_view_literals;
  constexpr std::string_view kConfigFileMessage =
      "configuration file, other arguments will overwrite the parameters read from the configuration file"sv;
  bool print, help;
  boost::program_options::options_description description("Allowed options");
  // clang-format off
  description.add_options()
      ("help,h", program_options::bool_switch(&help)->default_value(false),"produce help message")
      ("disable-logging,l","disable logging to file")
      ("print-configuration,p", program_options::bool_switch(&print)->default_value(false), "print configuration")
      ("configuration-file,f", program_options::value<std::string>(), kConfigFileMessage.data())
      ("my-id", program_options::value<std::size_t>(), "my party id")
      ("parties", program_options::value<std::vector<std::string>>()->multitoken(), "info (id,IP,port) for each party e.g., --parties 0,127.0.0.1,23000 1,127.0.0.1,23001")
      ("online-after-setup", program_options::value<bool>()->default_value(true), "compute the online phase of the gate evaluations after the setup phase for all of them is completed (true/1 or false/0)")
      ("repetitions", program_options::value<std::size_t>()->default_value(1), "number of repetitions")
      ("cnn", program_options::value<std::string>()->default_value("mnist"), "CNN (mnist, cifar10 or vgg16)");
  // clang-format on

  program_options::variables_map user_options;

  program_options::store(program_options::parse_command_line(ac, av, description), user_options);
  program_options::notify(user_options);

  // argument help or no arguments (at least a configuration file is expected)
  if (help) {
    std::cout << description << "\n";
    return std::make_pair<program_options::variables_map, bool>({}, true);
  }

  // read configuration file
  if (user_options.count("configuration-file")) {
    std::ifstream ifs(user_options["configuration-file"].as<std::string>().c_str());
    program_options::variables_map user_option_config_file;
    program_options::store(program_options::parse_config_file(ifs, description), user_options);
    program_options::notify(user_options);
  }

  // print parsed parameters
  if (user_options.count("my-id")) {
    if (print) std::cout << "My id " << user_options["my-id"].as<std::size_t>() << std::endl;
  } else
    throw std::runtime_error("My id is not set but required");

  if (user_options.count("cnn")) {
    if (print) std::cout << "CNN to benchmark: " << user_options["cnn"].as<std::string>() << std::endl;
  } else
    throw std::runtime_error("CNN is not set but required");

  if (user_options.count("parties")) {
    const std::vector<std::string> other_parties{
        user_options["parties"].as<std::vector<std::string>>()};
    std::string parties("Other parties: ");
    for (auto& party : other_parties) {
      if (CheckPartyArgumentSyntax(party)) {
        if (print) parties.append(" " + party);
      } else {
        throw std::runtime_error("Incorrect party argument syntax " + party);
      }
    }
    if (print) std::cout << parties << std::endl;
  } else
    throw std::runtime_error("Other parties' information is not set but required");

  if (print) {
    std::cout << "Number of SIMD AES evaluations: " << user_options["num-simd"].as<std::size_t>()
              << std::endl;

    std::cout << "MPC Protocol: " << user_options["protocol"].as<std::string>() << std::endl;
  }
  return std::make_pair(user_options, help);
}

encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options) {
  const auto parties_string{user_options["parties"].as<const std::vector<std::string>>()};
  const auto number_of_parties{parties_string.size()};
  const auto my_id{user_options["my-id"].as<std::size_t>()};
  if (my_id >= number_of_parties) {
    throw std::runtime_error(fmt::format(
        "My id needs to be in the range [0, #parties - 1], current my id is {} and #parties is {}",
        my_id, number_of_parties));
  }

  encrypto::motion::communication::TcpPartiesConfiguration parties_configuration(number_of_parties);

  for (const auto& party_string : parties_string) {
    const auto [party_id, host, port] = ParsePartyArgument(party_string);
    if (party_id >= number_of_parties) {
      throw std::runtime_error(
          fmt::format("Party's id needs to be in the range [0, #parties - 1], current id "
                      "is {} and #parties is {}",
                      party_id, number_of_parties));
    }
    parties_configuration.at(party_id) = std::make_pair(host, port);
  }
  encrypto::motion::communication::TcpSetupHelper helper(my_id, parties_configuration);
  auto communication_layer = std::make_unique<encrypto::motion::communication::CommunicationLayer>(
      my_id, helper.SetupConnections());
  auto party = std::make_unique<encrypto::motion::Party>(std::move(communication_layer));
  auto configuration = party->GetConfiguration();
  // disable logging if the corresponding flag was set
  const auto logging{!user_options.count("disable-logging")};
  configuration->SetLoggingEnabled(logging);
  configuration->SetOnlineAfterSetup(user_options["online-after-setup"].as<bool>());
  return party;
}