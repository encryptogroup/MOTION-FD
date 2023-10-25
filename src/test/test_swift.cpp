#include <gtest/gtest.h>
#include <algorithm>

#include "base/party.h"
#include "protocols/swift/swift_gate.h"
#include "protocols/swift/swift_wire.h"
#include "test_constants.h"
#include "test_helpers.h"

#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/vector.hpp>
#include <boost/numeric/ublas/io.hpp>

namespace mo = encrypto::motion;
namespace ublas = boost::numeric::ublas;

template<typename T>
mo::proto::swift::WirePointer<T> GetSwiftWire(mo::GatePointer const& gate) {
  return std::dynamic_pointer_cast<mo::proto::swift::Wire<T>>(gate->GetOutputWires()[0]);
} 

TEST(SwiftTest, InputOutput) {
  auto parties = mo::MakeLocallyConnectedParties(3, kPortOffset);
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != parties.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      mo::Backend& backend = *parties[party_id]->GetBackend();
      auto input_gate_0 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::InputGate<uint64_t>>(
          std::vector<uint64_t>{(party_id == 0) ? uint64_t(42) : uint64_t(0)}, 0, backend);
      auto input_gate_1 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::InputGate<uint64_t>>(
          std::vector<uint64_t>{(party_id == 1) ? uint64_t(43) : uint64_t(0)}, 1, backend);
      auto input_gate_2 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::InputGate<uint64_t>>(
          std::vector<uint64_t>{(party_id == 2) ? uint64_t(44) : uint64_t(0)}, 2, backend);
      auto output_gate_0 = backend.GetRegister()->EmplaceGate<mo::proto::swift::OutputGate<uint64_t>>(GetSwiftWire<uint64_t>(input_gate_0));
      auto output_gate_1 = backend.GetRegister()->EmplaceGate<mo::proto::swift::OutputGate<uint64_t>>(GetSwiftWire<uint64_t>(input_gate_1));
      auto output_gate_2 = backend.GetRegister()->EmplaceGate<mo::proto::swift::OutputGate<uint64_t>>(GetSwiftWire<uint64_t>(input_gate_2));
      
      parties[party_id]->Run();
      
      uint64_t result_0 = GetSwiftWire<uint64_t>(output_gate_0)->GetData().values[0];
      uint64_t result_1 = GetSwiftWire<uint64_t>(output_gate_1)->GetData().values[0];
      uint64_t result_2 = GetSwiftWire<uint64_t>(output_gate_2)->GetData().values[0];
      EXPECT_EQ(result_0, 42);
      EXPECT_EQ(result_1, 43);
      EXPECT_EQ(result_2, 44);
      parties[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
  
}

TEST(SwiftTest, Multiply) {
  auto parties = mo::MakeLocallyConnectedParties(3, kPortOffset);
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != parties.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      mo::Backend& backend = *parties[party_id]->GetBackend();
      auto input_gate_0 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::InputGate<uint64_t>>(
          std::vector<uint64_t>{(party_id == 0) ? uint64_t(42) : uint64_t(0)}, 0, backend);
      auto input_gate_1 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::InputGate<uint64_t>>(
          std::vector<uint64_t>{(party_id == 1) ? uint64_t(43) : uint64_t(0)}, 1, backend);
      auto input_gate_2 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::InputGate<uint64_t>>(
          std::vector<uint64_t>{(party_id == 2) ? uint64_t(44) : uint64_t(0)}, 2, backend);
          
      auto multiply_gate_0 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::MultiplicationGate<uint64_t>>(
          GetSwiftWire<uint64_t>(input_gate_0), GetSwiftWire<uint64_t>(input_gate_1));
      auto multiply_gate_1 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::MultiplicationGate<uint64_t>>(
          GetSwiftWire<uint64_t>(multiply_gate_0), GetSwiftWire<uint64_t>(input_gate_2));
      
      auto output_gate_0 = backend.GetRegister()->EmplaceGate<mo::proto::swift::OutputGate<uint64_t>>(GetSwiftWire<uint64_t>(multiply_gate_1));
      parties[party_id]->Run();
      
      uint64_t result_0 = GetSwiftWire<uint64_t>(output_gate_0)->GetData().values[0];
      EXPECT_EQ(result_0, 42 * 43 * 44);
      parties[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}


TEST(SwiftTest, MatrixMultiply) {
  using namespace boost::numeric::ublas;
  auto parties = mo::MakeLocallyConnectedParties(3, kPortOffset);
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  
  size_t u = 3;
  size_t w = 4;
  size_t v = 2;
  size_t x = 5;
      
  matrix<uint64_t> m1(u, w), m2(w, v), m3(v, x);
      
  for(size_t i = 0; i != u; ++i) {
    for(size_t j = 0; j != w; ++j) {
      m1(i, j) = 10*i + j;
    }
  }
  for(size_t i = 0; i != w; ++i) {
    for(size_t j = 0; j != v; ++j) {
      m2(i, j) = 10*i + j;
    }
  }
  for(size_t i = 0; i != v; ++i) {
    for(size_t j = 0; j != x; ++j) {
      m3(i, j) = 10*i + j;
    }
  }
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != parties.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      mo::Backend& backend = *parties[party_id]->GetBackend();
      
      matrix<std::shared_ptr<mo::proto::swift::InputGate<uint64_t>>> input_matrix_gates1(u, w);
      matrix<std::shared_ptr<mo::proto::swift::InputGate<uint64_t>>> input_matrix_gates2(w, v);
      matrix<std::shared_ptr<mo::proto::swift::InputGate<uint64_t>>> input_matrix_gates3(v, x);
      matrix<mo::proto::swift::WirePointer<uint64_t>> input_matrix_wires1(u, w);
      matrix<mo::proto::swift::WirePointer<uint64_t>> input_matrix_wires2(w, v);
      matrix<mo::proto::swift::WirePointer<uint64_t>> input_matrix_wires3(v, x);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != w; ++j) {
          size_t owner = (i * w + j) % 3;
          input_matrix_gates1(i, j) = 
            backend.GetRegister()->EmplaceGate<mo::proto::swift::InputGate<uint64_t>>(
              std::vector<uint64_t>{(party_id == owner) ? uint64_t(m1(i, j)) : uint64_t(0)}, owner, backend);
          input_matrix_wires1(i, j) = 
            GetSwiftWire<uint64_t>(input_matrix_gates1(i, j));
        }
      }
      for(size_t i = 0; i != w; ++i) {
        for(size_t j = 0; j != v; ++j) {
          size_t owner = (i * v + j) % 3;
          input_matrix_gates2(i, j) = 
            backend.GetRegister()->EmplaceGate<mo::proto::swift::InputGate<uint64_t>>(
              std::vector<uint64_t>{(party_id == owner) ? uint64_t(m2(i, j)) : uint64_t(0)}, owner, backend);
          input_matrix_wires2(i, j) = 
            GetSwiftWire<uint64_t>(input_matrix_gates2(i, j));
        }
      }
      for(size_t i = 0; i != v; ++i) {
        for(size_t j = 0; j != x; ++j) {
          size_t owner = (i * x + j) % 3;
          input_matrix_gates3(i, j) = 
            backend.GetRegister()->EmplaceGate<mo::proto::swift::InputGate<uint64_t>>(
              std::vector<uint64_t>{(party_id == owner) ? uint64_t(m3(i, j)) : uint64_t(0)}, owner, backend);
          input_matrix_wires3(i, j) = 
            GetSwiftWire<uint64_t>(input_matrix_gates3(i, j));
        }
      }
      
      //We need to first convert the input into a MatrixWire
      auto matrix_conversion_gate1 = 
          backend.GetRegister()->EmplaceGate<mo::proto::swift::MatrixConversionGate<uint64_t>>(
            input_matrix_wires1);
      auto matrix_conversion_gate2 = 
          backend.GetRegister()->EmplaceGate<mo::proto::swift::MatrixConversionGate<uint64_t>>(
            input_matrix_wires2);
      auto matrix_conversion_gate3 = 
          backend.GetRegister()->EmplaceGate<mo::proto::swift::MatrixConversionGate<uint64_t>>(
            input_matrix_wires3);
      auto matrix_conversion_wire1 = 
        std::dynamic_pointer_cast<mo::proto::swift::MatrixWire<uint64_t>>(
          matrix_conversion_gate1->GetOutputWires()[0]);
      auto matrix_conversion_wire2 = 
        std::dynamic_pointer_cast<mo::proto::swift::MatrixWire<uint64_t>>(
          matrix_conversion_gate2->GetOutputWires()[0]);
      auto matrix_conversion_wire3 = 
        std::dynamic_pointer_cast<mo::proto::swift::MatrixWire<uint64_t>>(
          matrix_conversion_gate3->GetOutputWires()[0]);
      //Now we can multiply the matrices.
      auto matrix_multiplication_gate1 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::MatrixMultiplicationGate<uint64_t>>(
          matrix_conversion_wire1, matrix_conversion_wire2);
      auto matrix_multiplication_wire1 =
        std::dynamic_pointer_cast<mo::proto::swift::MatrixWire<uint64_t>>(
          matrix_multiplication_gate1->GetOutputWires()[0]);
      auto matrix_multiplication_gate2 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::MatrixMultiplicationGate<uint64_t>>(
          matrix_multiplication_wire1, matrix_conversion_wire3);
      auto matrix_multiplication_wire2 =
        std::dynamic_pointer_cast<mo::proto::swift::MatrixWire<uint64_t>>(
          matrix_multiplication_gate2->GetOutputWires()[0]);
          
      //Before outputting the values, we need to fist reconvert the MatrixWire into a usual Wire
      auto matrix_reconversion_gate1 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::MatrixReconversionGate<uint64_t>>(
          matrix_multiplication_wire2);
      auto matrix_reconversion_wire_matrix1 = matrix_reconversion_gate1->GetWireMatrix();
      
      EXPECT_EQ(matrix_reconversion_wire_matrix1.size1(), u);
      EXPECT_EQ(matrix_reconversion_wire_matrix1.size2(), x);
      
      matrix<std::shared_ptr<mo::proto::swift::OutputGate<uint64_t>>> output_gate_matrix(
        matrix_reconversion_wire_matrix1.size1(), matrix_reconversion_wire_matrix1.size2());
      matrix<mo::proto::swift::WirePointer<uint64_t>> output_wire_matrix(
        matrix_reconversion_wire_matrix1.size1(), matrix_reconversion_wire_matrix1.size2());
      for(size_t i = 0; i != output_gate_matrix.size1(); ++i) {
        for(size_t j = 0; j != output_gate_matrix.size2(); ++j) {
          output_gate_matrix(i, j) =  
            backend.GetRegister()->EmplaceGate<mo::proto::swift::OutputGate<uint64_t>>(
              matrix_reconversion_wire_matrix1(i, j));
          output_wire_matrix(i, j) = 
            GetSwiftWire<uint64_t>(output_gate_matrix(i, j));
        }
      }
      
      parties[party_id]->Run();
      matrix<uint64_t> expected = prod(matrix<uint64_t>(prod(m1, m2)), m3);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != x; ++j) {
          EXPECT_EQ(output_wire_matrix(i, j)->GetData().values[0], expected(i, j));
        }
      }
      parties[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}


TEST(SwiftTest, MatrixConversionReconversion) {
  using namespace boost::numeric::ublas;
  auto parties = mo::MakeLocallyConnectedParties(3, kPortOffset);
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  
  size_t u = 3;
  size_t v = 4;
      
  matrix<uint64_t> m1(u, v);
      
  for(size_t i = 0; i != u; ++i) {
    for(size_t j = 0; j != v; ++j) {
      m1(i, j) = 10*i + j;
    }
  }
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != parties.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      mo::Backend& backend = *parties[party_id]->GetBackend();
      
      matrix<std::shared_ptr<mo::proto::swift::InputGate<uint64_t>>> input_matrix_gates1(u, v);
      matrix<mo::proto::swift::WirePointer<uint64_t>> input_matrix_wires1(u, v);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          size_t owner = (i * v + j) % 3;
          input_matrix_gates1(i, j) = 
            backend.GetRegister()->EmplaceGate<mo::proto::swift::InputGate<uint64_t>>(
              std::vector<uint64_t>{(party_id == owner) ? uint64_t(m1(i, j)) : uint64_t(0)}, owner, backend);
          input_matrix_wires1(i, j) = 
            GetSwiftWire<uint64_t>(input_matrix_gates1(i, j));
        }
      }
      
      //We need to first convert the input into a MatrixWire
      auto matrix_conversion_gate1 = 
          backend.GetRegister()->EmplaceGate<mo::proto::swift::MatrixConversionGate<uint64_t>>(
            input_matrix_wires1);
      auto matrix_conversion_wire1 = 
        std::dynamic_pointer_cast<mo::proto::swift::MatrixWire<uint64_t>>(
          matrix_conversion_gate1->GetOutputWires()[0]);
          
      //Before outputting the values, we need to fist reconvert the MatrixWire into a usual Wire
      auto matrix_reconversion_gate1 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::MatrixReconversionGate<uint64_t>>(
          matrix_conversion_wire1);
      auto matrix_reconversion_wire_matrix1 = matrix_reconversion_gate1->GetWireMatrix();
      
      
      matrix<std::shared_ptr<mo::proto::swift::OutputGate<uint64_t>>> output_gate_matrix(
        matrix_reconversion_wire_matrix1.size1(), matrix_reconversion_wire_matrix1.size2());
      matrix<mo::proto::swift::WirePointer<uint64_t>> output_wire_matrix(
        matrix_reconversion_wire_matrix1.size1(), matrix_reconversion_wire_matrix1.size2());
      for(size_t i = 0; i != output_gate_matrix.size1(); ++i) {
        for(size_t j = 0; j != output_gate_matrix.size2(); ++j) {
          output_gate_matrix(i, j) =  
            backend.GetRegister()->EmplaceGate<mo::proto::swift::OutputGate<uint64_t>>(
              matrix_reconversion_wire_matrix1(i, j));
          output_wire_matrix(i, j) = 
            GetSwiftWire<uint64_t>(output_gate_matrix(i, j));
        }
      }
      
      parties[party_id]->Run();
      matrix<uint64_t> expected = m1;
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          EXPECT_EQ(output_wire_matrix(i, j)->GetData().values[0], expected(i, j));
        }
      }
      parties[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TEST(SwiftTest, Msb) {
  using namespace boost::numeric::ublas;
  auto parties = mo::MakeLocallyConnectedParties(3, kPortOffset);
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  
  size_t u = 3;
  size_t v = 4;
      
  matrix<uint64_t> m1(u, v);
  matrix<uint64_t> expected(u, v);
      
  int64_t factor = 1;
  for(size_t i = 0; i != u; ++i) {
    for(size_t j = 0; j != v; ++j, factor *= -1) {
      m1(i, j) = (10*i + j) * factor;
      if(factor == 1) {
        expected(i, j) = 0;
      } else if(factor == -1) {
        expected(i, j) = 1;  
      } else {
        assert(false);
      }
    }
  }
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != parties.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      mo::Backend& backend = *parties[party_id]->GetBackend();
      
      matrix<std::shared_ptr<mo::proto::swift::InputGate<uint64_t>>> input_matrix_gates1(u, v);
      matrix<mo::proto::swift::WirePointer<uint64_t>> input_matrix_wires1(u, v);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          size_t owner = (i * v + j) % 3;
          input_matrix_gates1(i, j) = 
            backend.GetRegister()->EmplaceGate<mo::proto::swift::InputGate<uint64_t>>(
              std::vector<uint64_t>{(party_id == owner) ? uint64_t(m1(i, j)) : uint64_t(0)}, owner, backend);
          input_matrix_wires1(i, j) = 
            GetSwiftWire<uint64_t>(input_matrix_gates1(i, j));
        }
      }
      
      //We need to first convert the input into a MatrixWire
      auto matrix_conversion_gate1 = 
          backend.GetRegister()->EmplaceGate<mo::proto::swift::MatrixConversionGate<uint64_t>>(
            input_matrix_wires1);
      auto matrix_conversion_wire1 = 
        std::dynamic_pointer_cast<mo::proto::swift::MatrixWire<uint64_t>>(
          matrix_conversion_gate1->GetOutputWires()[0]);
          
      auto msb_gate1 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::MsbGate<uint64_t>>(
          matrix_conversion_wire1);
      auto msb_wire1 =
        std::dynamic_pointer_cast<mo::proto::swift::BitMatrixWire>(
          msb_gate1->GetOutputWires()[0]);
          
      auto bit_a_gate1 =
        backend.GetRegister()->EmplaceGate<mo::proto::swift::BitAGate<uint64_t>>(
          msb_wire1);
      auto bit_a_wire1 =
        std::dynamic_pointer_cast<mo::proto::swift::MatrixWire<uint64_t>>(
          bit_a_gate1->GetOutputWires()[0]);
          
      //Before outputting the values, we need to fist reconvert the MatrixWire into a usual Wire
      auto matrix_reconversion_gate1 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::MatrixReconversionGate<uint64_t>>(
          bit_a_wire1);
      auto matrix_reconversion_wire_matrix1 = matrix_reconversion_gate1->GetWireMatrix();
      
      matrix<std::shared_ptr<mo::proto::swift::OutputGate<uint64_t>>> output_gate_matrix(
        matrix_reconversion_wire_matrix1.size1(), matrix_reconversion_wire_matrix1.size2());
      matrix<mo::proto::swift::WirePointer<uint64_t>> output_wire_matrix(
        matrix_reconversion_wire_matrix1.size1(), matrix_reconversion_wire_matrix1.size2());
      for(size_t i = 0; i != output_gate_matrix.size1(); ++i) {
        for(size_t j = 0; j != output_gate_matrix.size2(); ++j) {
          output_gate_matrix(i, j) =  
            backend.GetRegister()->EmplaceGate<mo::proto::swift::OutputGate<uint64_t>>(
              matrix_reconversion_wire_matrix1(i, j));
          output_wire_matrix(i, j) = 
            GetSwiftWire<uint64_t>(output_gate_matrix(i, j));
        }
      }
      
      parties[party_id]->Run();
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != v; ++j) {
          EXPECT_EQ(output_wire_matrix(i, j)->GetData().values[0], expected(i, j));
        }
      }
      parties[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

/*
TEST(SwiftTest, BitA) {
  using namespace boost::numeric::ublas;
  auto parties = mo::MakeLocallyConnectedParties(3, kPortOffset);
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  
  size_t u = 3;
  size_t w = 4;
  
  mo::BitVector<> bit_m(u * w);
  for(size_t i = 0; i != u * w; ++i) {
    bit_m.Set(i % 2, i);
  }
      
  matrix<uint64_t> m1(u, w);
      
  for(size_t i = 0; i != u; ++i) {
    for(size_t j = 0; j != w; ++j) {
      m1(i, j) = (i*w + j) % 2;
    }
  }
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != parties.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      mo::Backend& backend = *parties[party_id]->GetBackend();
      
      
      matrix<std::shared_ptr<mo::proto::swift::InputGate<uint64_t>>> input_matrix_gates1(u, w);
      matrix<mo::proto::swift::WirePointer<uint64_t>> input_matrix_wires1(u, w);
      for(size_t i = 0; i != u; ++i) {
        for(size_t j = 0; j != w; ++j) {
          size_t owner = (i * w + j) % 3;
          input_matrix_gates1(i, j) = 
            backend.GetRegister()->EmplaceGate<mo::proto::swift::InputGate<uint64_t>>(
              std::vector<uint64_t>{(party_id == owner) ? uint64_t(m1(i, j)) : uint64_t(0)}, owner, backend);
          input_matrix_wires1(i, j) = 
            GetSwiftWire<uint64_t>(input_matrix_gates1(i, j));
        }
      }
      
      //We need to first convert the input into a MatrixWire
      auto matrix_conversion_gate1 = 
          backend.GetRegister()->EmplaceGate<mo::proto::swift::MatrixConversionGate<uint64_t>>(
            input_matrix_wires1);
      auto matrix_conversion_wire1 = 
        std::dynamic_pointer_cast<mo::proto::swift::MatrixWire<uint64_t>>(
          matrix_conversion_gate1->GetOutputWires()[0]);
      
      auto w1 = 
        backend.GetRegister()->EmplaceWire<mo::proto::swift::BitMatrixWire>(
          backend, bit_m, BitVector<>(u*w), BitVector(u*w) u, w, 1);
          
      backend.GetRegister()->EmplaceGate<mo::proto::swift::MatrixReconversionGate<uint64_t>>(
        matrix_conversion_wire1);
      
      
          
      //Before outputting the values, we need to fist reconvert the MatrixWire into a usual Wire
      auto matrix_reconversion_gate1 = 
        backend.GetRegister()->EmplaceGate<mo::proto::swift::MatrixReconversionGate<uint64_t>>(
          matrix_conversion_wire1);
      auto matrix_reconversion_wire_matrix1 = matrix_reconversion_gate1->GetWireMatrix();
      
      EXPECT_EQ(matrix_reconversion_wire_matrix1.size1(), u);
      EXPECT_EQ(matrix_reconversion_wire_matrix1.size2(), w);
      
      matrix<std::shared_ptr<mo::proto::swift::OutputGate<uint64_t>>> output_gate_matrix(
        matrix_reconversion_wire_matrix1.size1(), matrix_reconversion_wire_matrix1.size2());
      matrix<mo::proto::swift::WirePointer<uint64_t>> output_wire_matrix(
        matrix_reconversion_wire_matrix1.size1(), matrix_reconversion_wire_matrix1.size2());
      for(size_t i = 0; i != output_gate_matrix.size1(); ++i) {
        for(size_t j = 0; j != output_gate_matrix.size2(); ++j) {
          output_gate_matrix(i, j) =  
            backend.GetRegister()->EmplaceGate<mo::proto::swift::OutputGate<uint64_t>>(
              matrix_reconversion_wire_matrix1(i, j));
          output_wire_matrix(i, j) = 
            GetSwiftWire<uint64_t>(output_gate_matrix(i, j));
        }
      }
      
      parties[party_id]->Run();
      matrix<uint64_t> expected = m1;
      for(size_t i = 0; i != expected.size1(); ++i) {
        for(size_t j = 0; j != expected.size2(); ++j) {
          EXPECT_EQ(output_wire_matrix(i, j)->GetData().values[0], expected(i, j));
          EXPECT_EQ(bit_m.Get(i * expected.size2() + j), expected(i, j));
        }
      }
      parties[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}
*/

/*
constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max();
constexpr auto kAstra = encrypto::motion::MpcProtocol::kAstra;

namespace mo = encrypto::motion;
namespace ublas = boost::numeric::ublas;

template <typename T>
class AstraTest : public ::testing::Test {
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
              parties_.at(party_id)->template In<kAstra>(inputs_single_[input_owner], input_owner);
          shared_inputs_simd_[party_id][input_owner] =
              parties_.at(party_id)->template In<kAstra>(inputs_simd_[input_owner], input_owner);
        } else {
          shared_inputs_single_[party_id][input_owner] =
              parties_.at(party_id)->template In<kAstra>(zeros_single_, input_owner);
          shared_inputs_simd_[party_id][input_owner] =
              parties_.at(party_id)->template In<kAstra>(zeros_simd_, input_owner);
        }
      }
    }
  }

  void GenerateDotProductInputs() {
    zeros_single_.emplace_back(0);
    zeros_simd_.resize(number_of_simd_, 0);

    std::mt19937_64 mt(seed_);
    std::uniform_int_distribution<T> dist;

    for (auto& v : inputs_dot_product_single_) {
      v.resize(dot_product_vector_size_);
      for (T& t : v) t = dist(mt);
    }

    for (auto& vv : inputs_dot_product_simd_) {
      vv.resize(dot_product_vector_size_);
      for (auto& v : vv) {
        v.resize(number_of_simd_);
        for (T& t : v) t = dist(mt);
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
              parties_.at(party_id)->template In<kAstra>(
                  inputs_dot_product_single_[vector_i][element_j], input_owner);
          shared_dot_product_inputs_simd_[party_id][vector_i][element_j] =
              parties_.at(party_id)->template In<kAstra>(
                  inputs_dot_product_simd_[vector_i][element_j], input_owner);
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
                parties_.at(party_id)->template In<kAstra>(input_matrix(i, j), input_owner);
            } else {
              shared_matrix(i, j) = 
                parties_.at(party_id)->template In<kAstra>(T(0), input_owner);
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
TYPED_TEST_SUITE(AstraTest, UintTypes);

TYPED_TEST(AstraTest, InputOutput) {
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

TYPED_TEST(AstraTest, Addition) {
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

TYPED_TEST(AstraTest, Subtraction) {
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

TYPED_TEST(AstraTest, Multiplication) {
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

TYPED_TEST(AstraTest, DotProduct) {
  this->GenerateDotProductInputs();
  this->ShareDotProductInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id < this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_dp_single = mo::DotProduct(this->shared_dot_product_inputs_single_[party_id][0],
                                            this->shared_dot_product_inputs_single_[party_id][1]);
      auto share_dp_simd = mo::DotProduct(this->shared_dot_product_inputs_simd_[party_id][0],
                                          this->shared_dot_product_inputs_simd_[party_id][1]);

      auto share_output_single_all = share_dp_single.Out();    
      auto share_output_simd_all = share_dp_simd.Out();

      this->parties_[party_id]->Run();

      {
        TypeParam circuit_result_single = share_output_single_all.template As<TypeParam>();
        TypeParam expected_result_single = mo::DotProduct<TypeParam>(
            this->inputs_dot_product_single_[0], this->inputs_dot_product_single_[1]);
        EXPECT_EQ(circuit_result_single, expected_result_single);

        const std::vector<TypeParam> circuit_result_simd =
            share_output_simd_all.template As<std::vector<TypeParam>>();
        const std::vector<TypeParam> expected_result_simd = std::move(mo::RowDotProduct<TypeParam>(
            this->inputs_dot_product_simd_[0], this->inputs_dot_product_simd_[1]));
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}


TYPED_TEST(AstraTest, MatrixMultiplication) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::astra;
  
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


TYPED_TEST(AstraTest, FixedPointMatrixMultiplication) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::astra;
  
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


TYPED_TEST(AstraTest, HadamardMultiplication) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::astra;
  
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

std::vector<std::byte> ToByteVector2(mo::ShareWrapper output) {
  std::vector<std::byte> result;
  auto wires = output->GetWires();
  for(auto& wire : wires) {
    auto w = std::dynamic_pointer_cast<mo::proto::boolean_astra::Wire>(wire);
    auto& d = w->GetValues().GetData();
    std::copy(d.begin(), d.end(), std::back_inserter(result));
  }
  return result;
}

TYPED_TEST(AstraTest, Msb) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::astra;
  
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
      
      std::vector<std::byte> circuit_result = ToByteVector2(out_share_single);
      
      {
        mo::BitVector<> expected_result_single(n*m, false);
        for(size_t i = 0; i != m; ++i) {
          for(size_t j = 0; j != n; ++j) {
            expected_result_single.Set(bool((this->matrix_inputs_single_[0](i, j) >> (sizeof(TypeParam) * CHAR_BIT - 1))), i*n + j);
          }
        }
        expected_result_single.Invert();
          
        EXPECT_EQ(ToByteVector2(out_share_single), expected_result_single.GetData());
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TYPED_TEST(AstraTest, ReLU) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::astra;
  
  this->GenerateMatrixInputs();
  this->ShareMatrixInputs();
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mm_single = mo::ReLU(
        this->shared_matrix_inputs_single_[party_id][0]);
                                                      
      size_t m = this->shared_matrix_inputs_single_[party_id][0].size1();
      size_t n = this->shared_matrix_inputs_single_[party_id][0].size2();

      

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

TYPED_TEST(AstraTest, MaliciousReLU) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::astra;
  
  this->GenerateMatrixInputs();
  this->ShareMatrixInputs();
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mm_single = mo::MaliciousReLU(
        this->shared_matrix_inputs_single_[party_id][0]);
                                                      
      size_t m = this->shared_matrix_inputs_single_[party_id][0].size1();
      size_t n = this->shared_matrix_inputs_single_[party_id][0].size2();

      

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

TYPED_TEST(AstraTest, MaliciousMultiplication) {
  this->GenerateDiverseInputs();
  this->ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id < this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mul_single = MaliciousMultiply(
                                MaliciousMultiply(this->shared_inputs_single_[party_id][0],
                                                  this->shared_inputs_single_[party_id][1]),
                                this->shared_inputs_single_[party_id][2]
                              );
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

TYPED_TEST(AstraTest, MaliciousMatrixMultiplication) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::astra;
  
  this->GenerateMatrixInputs();
  this->ShareMatrixInputs();
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mm_single = mo::MaliciousMatrixMultiplication(
                               mo::MaliciousMatrixMultiplication(
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

TYPED_TEST(AstraTest, MaliciousHadamardMultiplication) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::astra;
  
  this->GenerateMatrixInputs();
  this->ShareMatrixInputs();
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mm_single = mo::MaliciousHadamardMultiplication(
                               mo::MaliciousHadamardMultiplication(
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

TYPED_TEST(AstraTest, MaliciousFixedPointMatrixMultiplication) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::astra;
  
  this->GenerateMatrixInputs();
  this->ShareMatrixInputs();
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mm_single = mo::MaliciousFixedPointMatrixMultiplication(
                               mo::MaliciousFixedPointMatrixMultiplication(
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
  for (auto& f : futures) f.get();constexpr 
}

TYPED_TEST(AstraTest, MaliciousMsb) {
  using namespace boost::numeric::ublas;
  using namespace mo::proto::astra;
  
  this->GenerateMatrixInputs();
  this->ShareMatrixInputs();
  
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mm_single = mo::MaliciousMatrixMsb(
        this->shared_matrix_inputs_single_[party_id][0]);
                                                      
      size_t m = this->shared_matrix_inputs_single_[party_id][0].size1();
      size_t n = this->shared_matrix_inputs_single_[party_id][0].size2();

      ublas::matrix<mo::ShareWrapper> out_share_matrix_single(m, n);
      auto out_share_single = share_mm_single.Out();
      
      this->parties_[party_id]->Run();
      
      std::vector<std::byte> circuit_result = ToByteVector2(out_share_single);
      
      {
        mo::BitVector<> expected_result_single(n*m, false);
        for(size_t i = 0; i != m; ++i) {
          for(size_t j = 0; j != n; ++j) {
            expected_result_single.Set(bool((this->matrix_inputs_single_[0](i, j) >> (sizeof(TypeParam) * CHAR_BIT - 1))), i*n + j);
          }
        }
        expected_result_single.Invert();
          
        EXPECT_EQ(ToByteVector2(out_share_single), expected_result_single.GetData());
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

*/