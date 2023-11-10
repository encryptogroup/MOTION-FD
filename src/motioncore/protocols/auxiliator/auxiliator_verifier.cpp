#include "base/backend.h"
#include "primitives/blake2b.h"
#include "communication/message_manager.h"
#include "communication/message.h"

#include "auxiliator_verifier.h"

#include <iomanip>

using namespace std::string_literals;

namespace encrypto::motion {
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

template<typename T>
std::string to_string(boost::numeric::ublas::matrix<T> const& m) {
  using std::to_string;
  std::string result = "[("s;
  for(size_t i = 0; i != m.size1(); ++i) {
    for(size_t j = 0; j != m.size2(); ++j) {
      result += to_string((uint16_t) m(i, j));
      if(j != m.size2()) result += ", "s;
    }
    result += ")"s;
  }
  result += "]"s;
  return result;
}

void Abort() {
  //throw std::runtime_error("Hashes do not match");
  
  //We do not actually abort, since we use garbage values during benchmarking.
  //Instead, we update a volatile counter to prevent the compiler from
  //optimizing out the function and the loop calling it.
  //Comment the lines below and uncomment the line above when running tests.
  static volatile std::atomic<size_t> counter = 0;
  counter.fetch_add(1, std::memory_order_relaxed);
}

}  // namespace (anonymous)

AuxiliatorSacrificeVerifier::ReservedTriple64::ReservedTriple64(
AuxiliatorSacrificeVerifier* sacrifice_verify, size_t offset)
: sacrifice_verify_{sacrifice_verify}, offset_{offset} {}

void AuxiliatorSacrificeVerifier::ReservedTriple64::AppendTriple(
uint64_t lambda_x, uint64_t lambda_y, uint64_t gamma_xy) {
  sacrifice_verify_->lambdas_x64_[offset_] = std::move(lambda_x);
  sacrifice_verify_->lambdas_y64_[offset_] = std::move(lambda_y);
  sacrifice_verify_->gammas_xy64_[offset_] = std::move(gamma_xy);
  ++offset_;
}

AuxiliatorSacrificeVerifier::ReservedTriple128::ReservedTriple128(
AuxiliatorSacrificeVerifier* sacrifice_verify, size_t offset)
: sacrifice_verify_{sacrifice_verify}, offset_{offset} {}

void AuxiliatorSacrificeVerifier::ReservedTriple128::AppendTriple(
UInt128 lambda_x, UInt128 lambda_y, UInt128 gamma_xy) {
  sacrifice_verify_->lambdas_x128_[offset_] = std::move(lambda_x);
  sacrifice_verify_->lambdas_y128_[offset_] = std::move(lambda_y);
  sacrifice_verify_->gammas_xy128_[offset_] = std::move(gamma_xy);
  ++offset_;
}

AuxiliatorSacrificeVerifier::ReservedMatrixTriple64::ReservedMatrixTriple64(
AuxiliatorSacrificeVerifier* sacrifice_verify, size_t offset)
: sacrifice_verify_{sacrifice_verify}, offset_{offset} {}

void AuxiliatorSacrificeVerifier::ReservedMatrixTriple64::AppendTriple(
  boost::numeric::ublas::matrix<uint64_t> lambda_x, 
  boost::numeric::ublas::matrix<uint64_t> lambda_y, 
  boost::numeric::ublas::matrix<uint64_t> gamma_xy) {
  sacrifice_verify_->matrix_lambdas_x64_[offset_] = std::move(lambda_x);
  sacrifice_verify_->matrix_lambdas_y64_[offset_] = std::move(lambda_y);
  sacrifice_verify_->matrix_gammas_xy64_[offset_] = std::move(gamma_xy);
  ++offset_;
}

AuxiliatorSacrificeVerifier::ReservedMatrixTriple128::ReservedMatrixTriple128(
AuxiliatorSacrificeVerifier* sacrifice_verify, size_t offset)
: sacrifice_verify_{sacrifice_verify}, offset_{offset} {}

void AuxiliatorSacrificeVerifier::ReservedMatrixTriple128::AppendTriple(
  boost::numeric::ublas::matrix<UInt128> lambda_x, 
  boost::numeric::ublas::matrix<UInt128> lambda_y, 
  boost::numeric::ublas::matrix<UInt128> gamma_xy) {
  sacrifice_verify_->matrix_lambdas_x128_[offset_] = std::move(lambda_x);
  sacrifice_verify_->matrix_lambdas_y128_[offset_] = std::move(lambda_y);
  sacrifice_verify_->matrix_gammas_xy128_[offset_] = std::move(gamma_xy);
  ++offset_;
}

AuxiliatorSacrificeVerifier::ReservedTriple64 
AuxiliatorSacrificeVerifier::ReserveTriples64(size_t number_of_triples) {
  //This method is supposed to be called during circuit definition, thus
  //no synchronization is needed here.
  dependencies_.fetch_add(1);
  size_t old_size = lambdas_x64_.size();
  lambdas_x64_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_y64_.size());
  lambdas_y64_.resize(old_size + number_of_triples);
  assert(old_size == gammas_xy64_.size());
  gammas_xy64_.resize(old_size + number_of_triples);
  return {this, old_size};
}

AuxiliatorSacrificeVerifier::ReservedTriple128 
AuxiliatorSacrificeVerifier::ReserveTriples128(size_t number_of_triples) {
  //This method is supposed to be called during circuit definition, thus
  //no synchronization is needed here.
  dependencies_.fetch_add(1);
  size_t old_size = lambdas_x128_.size();
  lambdas_x128_.resize(old_size + number_of_triples);
  assert(old_size == lambdas_y128_.size());
  lambdas_y128_.resize(old_size + number_of_triples);
  assert(old_size == gammas_xy128_.size());
  gammas_xy128_.resize(old_size + number_of_triples);
  return {this, old_size};
}

AuxiliatorSacrificeVerifier::ReservedMatrixTriple64 
AuxiliatorSacrificeVerifier::ReserveMatrixTriples64(size_t number_of_triples) {
  //This method is supposed to be called during circuit definition, thus
  //no synchronization is needed here.
  dependencies_.fetch_add(1);
  size_t old_size = matrix_lambdas_x64_.size();
  matrix_lambdas_x64_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_y64_.size());
  matrix_lambdas_y64_.resize(old_size + number_of_triples);
  assert(old_size == matrix_gammas_xy64_.size());
  matrix_gammas_xy64_.resize(old_size + number_of_triples);
  return {this, old_size};
}

AuxiliatorSacrificeVerifier::ReservedMatrixTriple128 
AuxiliatorSacrificeVerifier::ReserveMatrixTriples128(size_t number_of_triples) {
  //This method is supposed to be called during circuit definition, thus
  //no synchronization is needed here.
  dependencies_.fetch_add(1);
  size_t old_size = matrix_lambdas_x128_.size();
  matrix_lambdas_x128_.resize(old_size + number_of_triples);
  assert(old_size == matrix_lambdas_y128_.size());
  matrix_lambdas_y128_.resize(old_size + number_of_triples);
  assert(old_size == matrix_gammas_xy128_.size());
  matrix_gammas_xy128_.resize(old_size + number_of_triples);
  return {this, old_size};
}

AuxiliatorSacrificeVerifier::AuxiliatorSacrificeVerifier(Backend& backend)
: backend_{backend}, gate_id_{backend.GetRegister()->NextGateId()},
  dependencies_{2},
  check_is_done_condition_([this](){ return dependencies_.load() == 0; }),
  lambdas_x64_{}, lambdas_y64_{}, gammas_xy64_{},
  lambdas_x128_{}, lambdas_y128_{}, gammas_xy128_{} {
  using communication::MessageType::kAuxiliatorVerifier;
  auto& communication_layer = backend_.GetCommunicationLayer();
  auto& message_manager = communication_layer.GetMessageManager();
  uint64_t my_id = communication_layer.GetMyId();
  
  if (my_id == 1) {
    triple_future_p1_p2_ = message_manager.RegisterReceive(2, kAuxiliatorVerifier, gate_id_);
  } else if (my_id == 2) {
    triple_future_p0_ = message_manager.RegisterReceive(0, kAuxiliatorVerifier, gate_id_);
    triple_future_p1_p2_ = message_manager.RegisterReceive(1, kAuxiliatorVerifier, gate_id_);
  }
}

void AuxiliatorSacrificeVerifier::SetReady() {
  size_t dependencies = dependencies_.fetch_sub(1) - 1;
  //If dependencies is 1 at this point, all dependencies called SetReady()
  if(dependencies == 1) {
    Verify();
    //We need to set check_dependencies to 0, to notify all dependencies
    dependencies_.store(0);
    check_is_done_condition_.NotifyAll();
  }
}


void AuxiliatorSacrificeVerifier::Verify() {
  using communication::MessageType::kAuxiliatorVerifier;
  using boost::numeric::ublas::matrix;
  auto& communication_layer = backend_.GetCommunicationLayer();
  uint64_t my_id = communication_layer.GetMyId();
  
  //The number of scalar triples
  size_t const number_of_triples64 = lambdas_x64_.size();
  size_t const number_of_triples128 = lambdas_x128_.size();
  assert(number_of_triples64 == lambdas_y64_.size());
  assert(number_of_triples64 == gammas_xy64_.size());
  assert(number_of_triples128 == lambdas_y128_.size());
  assert(number_of_triples128 == gammas_xy128_.size());
  
  //The number of matrix triples
  size_t const number_of_matrix_triples64 = matrix_lambdas_x64_.size();
  size_t const number_of_matrix_triples128 = matrix_lambdas_x128_.size();
  assert(number_of_matrix_triples64 == matrix_lambdas_y64_.size());
  assert(number_of_matrix_triples64 == matrix_gammas_xy64_.size());
  assert(number_of_matrix_triples128 == matrix_lambdas_y128_.size());
  assert(number_of_matrix_triples128 == matrix_gammas_xy128_.size());
  
  //If triples are empty, there's nothing to do. 
  if(number_of_triples64 + number_of_triples128 
     + number_of_matrix_triples64 + number_of_matrix_triples128 == 0) {
    return;
  }
  size_t const number_of_triples64_bytes = number_of_triples64 * sizeof(uint64_t);
  size_t const number_of_triples128_bytes = number_of_triples128 * sizeof(UInt128);
  
  //Calculate the number of bytes used for a u x w and u x v matrix
  //of 64-bit scalar values
  size_t number_of_matrix_u_w64_bytes = 0;
  size_t number_of_matrix_u_v64_bytes = 0;
  for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
    size_t const u = matrix_lambdas_x64_[i].size1();
    size_t const w = matrix_lambdas_x64_[i].size2();
    size_t const v = matrix_lambdas_y64_[i].size2();
    assert(matrix_lambdas_y64_[i].size1() == w);
    assert(matrix_gammas_xy64_[i].size1() == u);
    assert(matrix_gammas_xy64_[i].size2() == v);
    number_of_matrix_u_w64_bytes += u * w * sizeof(uint64_t);
    number_of_matrix_u_v64_bytes += u * v * sizeof(uint64_t);
  }
  
  //Calculate the number of bytes used for a u x w and u x v matrix
  //of 128-bit scalar values
  size_t number_of_matrix_u_w128_bytes = 0;
  size_t number_of_matrix_u_v128_bytes = 0;
  for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
    size_t const u = matrix_lambdas_x128_[i].size1();
    size_t const w = matrix_lambdas_x128_[i].size2();
    size_t const v = matrix_lambdas_y128_[i].size2();
    assert(matrix_lambdas_y128_[i].size1() == w);
    assert(matrix_gammas_xy128_[i].size1() == u);
    assert(matrix_gammas_xy128_[i].size2() == v);
    number_of_matrix_u_w128_bytes += u * w * sizeof(UInt128);
    number_of_matrix_u_v128_bytes += u * v * sizeof(UInt128);
  }
  
  //Calculate the number of bytes used in the vectors for the respective variables
  size_t const number_of_triple_bytes = 
    number_of_triples64_bytes + number_of_triples128_bytes;
  size_t const number_of_matrix_u_w_bytes = 
    number_of_matrix_u_w64_bytes + number_of_matrix_u_w128_bytes;
  size_t const number_of_matrix_u_v_bytes = 
    number_of_matrix_u_v64_bytes + number_of_matrix_u_v128_bytes;
  size_t const lambda1_x_prime_gamma1_x_prime_y_bytes = 
    number_of_triple_bytes + number_of_matrix_u_w_bytes 
    + number_of_triple_bytes + number_of_matrix_u_v_bytes;
  size_t const lambda2_x_prime_bytes = 
    number_of_triple_bytes + number_of_matrix_u_w_bytes;
  size_t const gamma2_x_prime_bytes =
    number_of_triple_bytes + number_of_matrix_u_v_bytes;
  size_t const v_bytes = 
    number_of_triple_bytes + number_of_matrix_u_w_bytes;
  size_t const w_bytes = 
    number_of_triple_bytes + number_of_matrix_u_v_bytes;
  
  //Calculate the offset of each element in the random number vectors
  size_t const lambda1_x_prime64_offset = 0;
  size_t const lambda1_x_prime128_offset = 
    lambda1_x_prime64_offset + number_of_triples64_bytes;
  size_t const gamma1_x_prime_y64_offset = 
    lambda1_x_prime128_offset + number_of_triples128_bytes;
  assert(gamma1_x_prime_y64_offset == number_of_triple_bytes);
  size_t const gamma1_x_prime_y128_offset = 
    gamma1_x_prime_y64_offset + number_of_triples64_bytes;
  size_t const matrix_lambda1_x_prime64_offset = 
    gamma1_x_prime_y128_offset + number_of_triples128_bytes;
  assert(matrix_lambda1_x_prime64_offset == 2*number_of_triple_bytes);
  size_t const matrix_lambda1_x_prime128_offset = 
    matrix_lambda1_x_prime64_offset + number_of_matrix_u_w64_bytes;
  size_t const matrix_gamma1_x_prime_y64_offset = 
    matrix_lambda1_x_prime128_offset + number_of_matrix_u_w128_bytes;
  assert(matrix_gamma1_x_prime_y64_offset 
         == 2*number_of_triple_bytes + number_of_matrix_u_w_bytes);
  size_t const matrix_gamma1_x_prime_y128_offset = 
    matrix_gamma1_x_prime_y64_offset + number_of_matrix_u_v64_bytes;
  assert(matrix_gamma1_x_prime_y128_offset + number_of_matrix_u_v128_bytes
         == 2*number_of_triple_bytes + number_of_matrix_u_w_bytes 
            + number_of_matrix_u_v_bytes);
  
  size_t const lambda2_x_prime64_offset = 0;
  size_t const lambda2_x_prime128_offset = 
    lambda2_x_prime64_offset + number_of_triples64_bytes;
  assert(lambda2_x_prime128_offset + number_of_triples128_bytes == number_of_triple_bytes);
  size_t const matrix_lambda2_x_prime64_offset =
    lambda2_x_prime128_offset + number_of_triples128_bytes;
  size_t const matrix_lambda2_x_prime128_offset =
    matrix_lambda2_x_prime64_offset + number_of_matrix_u_w64_bytes;
  assert(matrix_lambda2_x_prime128_offset + number_of_matrix_u_w128_bytes 
         == number_of_triple_bytes + number_of_matrix_u_w_bytes);
  
  size_t const gamma2_x_prime_y64_offset = 0;
  size_t const gamma2_x_prime128_offset = 
    gamma2_x_prime_y64_offset + number_of_triples64_bytes;
  assert(gamma2_x_prime128_offset + number_of_triples128_bytes == number_of_triple_bytes);
  size_t const matrix_gamma2_x_prime_y64_offset =
    gamma2_x_prime128_offset + number_of_triples128_bytes;
  size_t const matrix_gamma2_x_prime_y128_offset =
    matrix_gamma2_x_prime_y64_offset + number_of_matrix_u_v64_bytes;
  assert(matrix_gamma2_x_prime_y128_offset + number_of_matrix_u_v128_bytes 
         == number_of_triple_bytes + number_of_matrix_u_v_bytes);
         
  size_t const v64_offset = 0;
  size_t const v128_offset = 
    v64_offset + number_of_triples64_bytes;
  size_t const matrix_v64_offset = 
    v128_offset + number_of_triples128_bytes;
  size_t const matrix_v128_offset =
    matrix_v64_offset + number_of_matrix_u_w64_bytes;
    
  size_t const w64_offset = 0;
  size_t const w128_offset = 
    v64_offset + number_of_triples64_bytes;
  size_t const matrix_w64_offset = 
    v128_offset + number_of_triples128_bytes;
  size_t const matrix_w128_offset =
    matrix_v64_offset + number_of_matrix_u_v64_bytes;
    
  //Inner functions assigning arrays of bytes to matrices and assigning
  //matrices to arrays of bytes
  auto AssignToMatrix = [](auto& mat, uint8_t const* data_pointer) {
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
  
  auto AssignFromMatrix = [](uint8_t* data_pointer, auto const& mat) {
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
  
  switch(my_id) {
    case 0: {
      auto& rng1 = backend_.GetBaseProvider().GetMyRandomnessGenerator(1);
      auto& rng2 = backend_.GetBaseProvider().GetMyRandomnessGenerator(2);
      //lambda1_x's are followed by gamma_x'ys, then followed by matrix_lambda_x'ys,
      //then finally followed by matrix_gamma_x'ys
      std::vector<uint8_t> randoms1 = 
        rng1.template GetUnsigned<uint8_t>(gate_id_, lambda1_x_prime_gamma1_x_prime_y_bytes);
      //lambda2_x's are at [0,..., number_of_triple_bytes)
      std::vector<uint8_t> randoms2 = 
        rng2.template GetUnsigned<uint8_t>(gate_id_, lambda2_x_prime_bytes);
      std::vector<uint8_t> gamma2_x_prime_y(gamma2_x_prime_bytes);
      
      //Calcuate gamma2_x'y
      {
        //Set the pointer to the first element to be read in the random byte array
        uint8_t const* const lambda1_x_prime64_pointer = 
          randoms1.data() + lambda1_x_prime64_offset;
        uint8_t const* const gamma1_x_prime_y64_pointer =
          randoms1.data() + gamma1_x_prime_y64_offset;
        uint8_t const* const lambda2_x_prime64_pointer =
          randoms2.data() + lambda2_x_prime64_offset;
        uint8_t* const gamma2_x_prime_y64_pointer =
          gamma2_x_prime_y.data() + gamma2_x_prime_y64_offset;
        size_t offset = 0;
        for(size_t i = 0; i != number_of_triples64; ++i) {
          //Convert the bytes in the random array to 64-bit values
          uint64_t lambda1_x_prime64;
          memcpy(&lambda1_x_prime64, lambda1_x_prime64_pointer + offset, sizeof(uint64_t));
          uint64_t lambda2_x_prime64;
          memcpy(&lambda2_x_prime64, lambda2_x_prime64_pointer + offset, sizeof(uint64_t));
          uint64_t lambda_y64 = lambdas_y64_[i];
          uint64_t gamma1_x_prime_y64;
          memcpy(&gamma1_x_prime_y64, gamma1_x_prime_y64_pointer + offset, sizeof(uint64_t));
          
          //Calculate gamma2_x'y
          uint64_t lambda_x_prime64 = lambda1_x_prime64 + lambda2_x_prime64;
          uint64_t gamma2_x_prime_y64 = lambda_x_prime64 * lambda_y64 - gamma1_x_prime_y64;
          
          //Store gamma2_x'y
          memcpy(gamma2_x_prime_y64_pointer + offset, &gamma2_x_prime_y64, sizeof(uint64_t));
          //Update offset
          offset += sizeof(uint64_t);
        }
        //128-bit values should follow 64-bit values
        assert(lambda1_x_prime64_offset + offset == lambda1_x_prime128_offset);
        assert(gamma1_x_prime_y64_offset + offset == gamma1_x_prime_y128_offset);
        assert(lambda2_x_prime64_offset + offset == lambda2_x_prime128_offset);
        assert(gamma2_x_prime_y64_offset + offset == gamma2_x_prime128_offset);
      }
      
      {
        //Same as above but with 128-bit values instead of 64-bit
        uint8_t const* const lambda1_x_prime128_pointer = 
          randoms1.data() + lambda1_x_prime128_offset;
        uint8_t const* const gamma1_x_prime_y128_pointer = 
          randoms1.data() + gamma1_x_prime_y128_offset;
        uint8_t const* const lambda2_x_prime128_pointer = 
          randoms2.data() + lambda2_x_prime128_offset;
        uint8_t* const gamma2_x_prime_y128_pointer = 
          gamma2_x_prime_y.data() + gamma2_x_prime128_offset;
        size_t offset = 0;
        for(size_t i = 0; i != number_of_triples128; ++i) {
          UInt128 lambda1_x_prime128;
          memcpy(&lambda1_x_prime128, lambda1_x_prime128_pointer + offset, sizeof(UInt128));
          UInt128 lambda2_x_prime128;
          memcpy(&lambda2_x_prime128, lambda2_x_prime128_pointer + offset, sizeof(UInt128));
          UInt128 lambda_y128 = lambdas_y128_[i];
          UInt128 gamma1_x_prime_y128;
          memcpy(&gamma1_x_prime_y128, gamma1_x_prime_y128_pointer + offset, sizeof(UInt128));
        
          UInt128 lambda_x_prime128 = lambda1_x_prime128 + lambda2_x_prime128;
          UInt128 gamma2_x_prime_y128 = lambda_x_prime128 * lambda_y128 - gamma1_x_prime_y128;
        
          memcpy(gamma2_x_prime_y128_pointer + offset, &gamma2_x_prime_y128, sizeof(UInt128));
          offset += sizeof(UInt128);
        }
        //gamma 64-bit values should follow lambda 128-bit values
        assert(lambda1_x_prime128_offset + offset == gamma1_x_prime_y64_offset);
        //matrix lambda 64-bit values should follow gamma_x'y 128-bit values
        assert(gamma1_x_prime_y128_offset + offset == matrix_lambda1_x_prime64_offset);
        //With lambda2 and gamma2,  the matrix 64-bit values follow directly after the 128-bit values
        assert(lambda2_x_prime128_offset + offset == matrix_lambda2_x_prime64_offset);
        assert(gamma2_x_prime128_offset + offset == matrix_gamma2_x_prime_y64_offset);
      }
      
      {
        //Same as the two above, but this time we work with matrices
        //of two different sizes u x w and u x v
        uint8_t const* const matrix_lambda1_x_prime64_pointer = 
          randoms1.data() + matrix_lambda1_x_prime64_offset;
        uint8_t const* const matrix_gamma1_x_prime_y64_pointer = 
          randoms1.data() + matrix_gamma1_x_prime_y64_offset;
        uint8_t const* const matrix_lambda2_x_prime64_pointer = 
          randoms2.data() + matrix_lambda2_x_prime64_offset;
        uint8_t* const matrix_gamma2_x_prime_y64_pointer = 
          gamma2_x_prime_y.data() + matrix_gamma2_x_prime_y64_offset;
        size_t u_w_offset = 0;
        size_t u_v_offset = 0;
        for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
          size_t const u = matrix_lambdas_x64_[i].size1();
          size_t const w = matrix_lambdas_x64_[i].size2();
          size_t const v = matrix_lambdas_y64_[i].size2();
          matrix<uint64_t> matrix_lambda1_x_prime64(u, w);
          AssignToMatrix(matrix_lambda1_x_prime64, matrix_lambda1_x_prime64_pointer + u_w_offset);
          matrix<uint64_t> matrix_lambda2_x_prime64(u, w);
          AssignToMatrix(matrix_lambda2_x_prime64, matrix_lambda2_x_prime64_pointer + u_w_offset);
          matrix<uint64_t> matrix_gamma1_x_prime_y64(u, v);
          AssignToMatrix(matrix_gamma1_x_prime_y64, matrix_gamma1_x_prime_y64_pointer + u_v_offset);
          matrix_gamma1_x_prime_y64 = 
            prod(matrix_lambda1_x_prime64 + matrix_lambda2_x_prime64, 
                 matrix_lambdas_y64_[i]) 
            - matrix_gamma1_x_prime_y64;
          AssignFromMatrix(matrix_gamma2_x_prime_y64_pointer + u_v_offset, matrix_gamma1_x_prime_y64);
          //Update the two offsets to point to the beginning of the data of the next matrix
          u_w_offset += u * w * sizeof(uint64_t);
          u_v_offset += u * v * sizeof(uint64_t);
        }
        //The matrix 64-bit values should be followed by matrix 128-bit values
        assert(matrix_lambda1_x_prime64_offset + u_w_offset == matrix_lambda1_x_prime128_offset);
        assert(matrix_gamma1_x_prime_y64_offset + u_v_offset == matrix_gamma1_x_prime_y128_offset);
        assert(matrix_lambda2_x_prime64_offset + u_w_offset == matrix_lambda2_x_prime128_offset);
        assert(matrix_gamma2_x_prime_y64_offset + u_v_offset == matrix_gamma2_x_prime_y128_offset);
      }
      
      {
        //Same as matrix above, but with 128-bit values instead of 64-bit
        uint8_t const* const matrix_lambda1_x_prime128_pointer = 
          randoms1.data() + matrix_lambda1_x_prime128_offset;
        uint8_t const* const matrix_gamma1_x_prime_y128_pointer = 
          randoms1.data() + matrix_gamma1_x_prime_y128_offset;
        uint8_t const* const matrix_lambda2_x_prime128_pointer = 
          randoms2.data() + matrix_lambda2_x_prime128_offset;
        uint8_t* const matrix_gamma2_x_prime_y128_pointer = 
          gamma2_x_prime_y.data() + matrix_gamma2_x_prime_y128_offset;
        size_t u_w_offset = 0;
        size_t u_v_offset = 0;
        for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
          size_t const u = matrix_lambdas_x128_[i].size1();
          size_t const w = matrix_lambdas_x128_[i].size2();
          size_t const v = matrix_lambdas_y128_[i].size2();
          matrix<UInt128> matrix_lambda1_x_prime128(u, w);
          AssignToMatrix(matrix_lambda1_x_prime128, matrix_lambda1_x_prime128_pointer + u_w_offset);
          matrix<UInt128> matrix_lambda2_x_prime128(u, w);
          AssignToMatrix(matrix_lambda2_x_prime128, matrix_lambda2_x_prime128_pointer + u_w_offset);
          matrix<UInt128> matrix_gamma1_x_prime_y128(u, v);
          AssignToMatrix(matrix_gamma1_x_prime_y128, matrix_gamma1_x_prime_y128_pointer + u_v_offset);
          matrix_gamma1_x_prime_y128 = 
            prod(matrix_lambda1_x_prime128 + matrix_lambda2_x_prime128, 
                 matrix_lambdas_y128_[i]) 
            - matrix_gamma1_x_prime_y128;
          AssignFromMatrix(matrix_gamma2_x_prime_y128_pointer + u_v_offset, matrix_gamma1_x_prime_y128);
          u_w_offset += u * w * sizeof(UInt128);
          u_v_offset += u * v * sizeof(UInt128);
        }
        assert(matrix_lambda1_x_prime128_offset + u_w_offset == matrix_gamma1_x_prime_y64_offset);
        assert(matrix_gamma1_x_prime_y128_offset + u_v_offset == randoms1.size());
        assert(matrix_lambda2_x_prime128_offset + u_w_offset == randoms2.size());
        assert(matrix_gamma2_x_prime_y128_offset + u_v_offset == gamma2_x_prime_y.size());
      }
      //Send gamma2_x'y to S2
      auto message = communication::BuildMessage(kAuxiliatorVerifier, gate_id_, gamma2_x_prime_y);
      communication_layer.SendMessage(2, message.Release());
      break;
    }
    case 1: {
      auto& rng0 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(0);
      auto& rng2 = backend_.GetBaseProvider().GetMyRandomnessGenerator(2);
      //lambda1_x's are followed by gamma_x'ys then followed by matrix_lambda_x'ys,
      //then finally followed by matrix_gamma_x'ys
      std::vector<uint8_t> randoms0 = 
        rng0.template GetUnsigned<uint8_t>(gate_id_, lambda1_x_prime_gamma1_x_prime_y_bytes);
      //Only one random value shared between S1 and S2 is enough for the protocol
      UInt128 r128 = rng2.template GetUnsigned<UInt128>(gate_id_, 1)[0];
      uint64_t r64 = uint64_t(r128);
      
      //m contains v1 and the hash of w
      std::vector<uint8_t> m(v_bytes + EVP_MAX_MD_SIZE);
      auto& v1 = m;
      
      //Calculate v1
      {
        uint8_t const* const lambda1_x_prime64_pointer = 
          randoms0.data() + lambda1_x_prime64_offset;
        uint8_t* const v1_64_pointer = v1.data() + v64_offset;
        size_t offset = 0;
        for(size_t i = 0; i != number_of_triples64; ++i) {
          uint64_t lambda1_x_prime64;
          memcpy(&lambda1_x_prime64, lambda1_x_prime64_pointer + offset, sizeof(uint64_t));
          uint64_t lambda1_x64 = lambdas_x64_[i];
        
          uint64_t v1_64 = r64 * lambda1_x64 - lambda1_x_prime64;
          memcpy(v1_64_pointer + offset, &v1_64, sizeof(uint64_t));
          offset += sizeof(uint64_t); 
        }
        assert(lambda1_x_prime64_offset + offset == lambda1_x_prime128_offset);
        assert(v64_offset + offset == v128_offset);
      }
      
      {
        uint8_t const* const lambda1_x_prime128_pointer = 
          randoms0.data() + lambda1_x_prime128_offset;
        uint8_t* const v1_128_pointer = v1.data() + v128_offset;
        size_t offset = 0;
        for(size_t i = 0; i != number_of_triples128; ++i) {
          UInt128 lambda1_x_prime128;
          memcpy(&lambda1_x_prime128, lambda1_x_prime128_pointer + offset, sizeof(UInt128));
          UInt128 lambda1_x128 = lambdas_x128_[i];
        
          UInt128 v1_128 = r128 * lambda1_x128 - lambda1_x_prime128;
          memcpy(v1_128_pointer + offset, &v1_128, sizeof(UInt128));
          offset += sizeof(UInt128);
        }
        assert(lambda1_x_prime128_offset + offset == gamma1_x_prime_y64_offset);
        assert(v128_offset + offset == matrix_v64_offset);
      }
      
      {
        uint8_t const* const matrix_lambda1_x_prime64_pointer = 
          randoms0.data() + matrix_lambda1_x_prime64_offset;
        uint8_t* const matrix_v1_64_pointer = v1.data() + matrix_v64_offset;
        size_t u_w_offset = 0;
        for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
          size_t const u = matrix_lambdas_x64_[i].size1();
          size_t const w = matrix_lambdas_x64_[i].size2();
          matrix<uint64_t> matrix_lambda_x_prime64(u, w);
          AssignToMatrix(matrix_lambda_x_prime64, 
                         matrix_lambda1_x_prime64_pointer + u_w_offset);
          matrix<uint64_t> matrix_v1_64 =
            r64 * matrix_lambdas_x64_[i] - matrix_lambda_x_prime64;
          AssignFromMatrix(matrix_v1_64_pointer + u_w_offset, matrix_v1_64);
          u_w_offset += u * w * sizeof(uint64_t); 
        }
        assert(matrix_lambda1_x_prime64_offset + u_w_offset == matrix_lambda1_x_prime128_offset);
        assert(matrix_v64_offset + u_w_offset == matrix_v128_offset);
      }
      
      {
        uint8_t const* const matrix_lambda1_x_prime128_pointer = 
          randoms0.data() + matrix_lambda1_x_prime128_offset;
        uint8_t* const matrix_v1_128_pointer = v1.data() + matrix_v128_offset;
        size_t u_w_offset = 0;
        for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
          size_t const u = matrix_lambdas_x128_[i].size1();
          size_t const w = matrix_lambdas_x128_[i].size2();
          matrix<UInt128> matrix_lambda_x_prime128(u, w);
          AssignToMatrix(matrix_lambda_x_prime128, 
                         matrix_lambda1_x_prime128_pointer + u_w_offset);
          matrix<UInt128> matrix_v1_128 = 
            r128 * matrix_lambdas_x128_[i] - matrix_lambda_x_prime128;
          AssignFromMatrix(matrix_v1_128_pointer + u_w_offset, matrix_v1_128);
          u_w_offset += u * w * sizeof(UInt128); 
        }
        assert(matrix_lambda1_x_prime128_offset + u_w_offset == matrix_gamma1_x_prime_y64_offset);
        assert(matrix_v128_offset + u_w_offset == v_bytes);
      }
      
      auto message = triple_future_p1_p2_.get();
      auto payload = communication::GetMessage(message.data())->payload();
      
      std::span<uint8_t const> v2{payload->Data(), payload->size()};
      assert(v2.size() == v_bytes);
      
      std::vector<uint8_t> w(w_bytes);
    
      //Calculate w
      {
        uint8_t const* const gamma1_x_prime_y64_pointer = 
          randoms0.data() + gamma1_x_prime_y64_offset;
        uint8_t const* const v1_64_pointer = v1.data() + v64_offset;
        uint8_t const* const v2_64_pointer = v2.data() + v64_offset;
        uint8_t* const w64_pointer = w.data() + w64_offset;
        size_t offset = 0;
        for(size_t i = 0; i != number_of_triples64; ++i) {
          uint64_t gamma1_x_prime_y64;
          memcpy(&gamma1_x_prime_y64, gamma1_x_prime_y64_pointer + offset, sizeof(uint64_t));
          uint64_t v1_64;
          memcpy(&v1_64, v1_64_pointer + offset, sizeof(uint64_t));
          uint64_t v2_64;
          memcpy(&v2_64, v2_64_pointer + offset, sizeof(uint64_t));
          uint64_t lambda1_y64 = lambdas_y64_[i];
          uint64_t gamma1_xy64 = gammas_xy64_[i];
        
          uint64_t v64 = v1_64 + v2_64;
          uint64_t w64 = v64 * lambda1_y64 - r64 * gamma1_xy64 + gamma1_x_prime_y64;
          memcpy(w64_pointer + offset, &w64, sizeof(uint64_t));
          offset += sizeof(uint64_t);
        }
        assert(gamma1_x_prime_y64_offset + offset == gamma1_x_prime_y128_offset);
        assert(v64_offset + offset == v128_offset);
        assert(w64_offset + offset == w128_offset);
      }
      
      {
        uint8_t const* const gamma1_x_prime_y128_pointer = 
          randoms0.data() + gamma1_x_prime_y128_offset;
        uint8_t const* const v1_128_pointer = v1.data() + v128_offset;
        uint8_t const* const v2_128_pointer = v2.data() + v128_offset;
        uint8_t* const w128_pointer = w.data() + w128_offset;
        size_t offset = 0;
        for(size_t i = 0; i != number_of_triples128; ++i) {
          UInt128 gamma1_x_prime_y128;
          memcpy(&gamma1_x_prime_y128, gamma1_x_prime_y128_pointer + offset, sizeof(UInt128));
          UInt128 v1_128;
          memcpy(&v1_128, v1_128_pointer + offset, sizeof(UInt128));
          UInt128 v2_128;
          memcpy(&v2_128, v2_128_pointer + offset, sizeof(UInt128));
          UInt128 lambda1_y128 = lambdas_y128_[i];
          UInt128 gamma1_xy128 = gammas_xy128_[i];
        
          UInt128 v128 = v1_128 + v2_128;
          UInt128 w128 = v128 * lambda1_y128 - r128 * gamma1_xy128 + gamma1_x_prime_y128;
          memcpy(w128_pointer + offset, &w128, sizeof(UInt128));
          offset += sizeof(UInt128);
        }
        assert(gamma1_x_prime_y128_offset + offset == matrix_lambda1_x_prime64_offset);
        assert(v128_offset + offset == matrix_v64_offset);
        assert(w128_offset + offset == matrix_w64_offset);
      }
      
      {
        uint8_t const* const matrix_gamma1_x_prime_y64_pointer = 
          randoms0.data() + matrix_gamma1_x_prime_y64_offset;
        uint8_t const* const matrix_v1_64_pointer = v1.data() + matrix_v64_offset;
        uint8_t const* const matrix_v2_64_pointer = v2.data() + matrix_v64_offset;
        uint8_t* const matrix_w64_pointer = w.data() + matrix_w64_offset;
        size_t u_w_offset = 0;
        size_t u_v_offset = 0;
        for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
          size_t const u = matrix_lambdas_x64_[i].size1();
          size_t const w = matrix_lambdas_x64_[i].size2();
          size_t const v = matrix_lambdas_y64_[i].size2();
          matrix<uint64_t> matrix_gamma1_x_prime_y64(u, v);
          AssignToMatrix(matrix_gamma1_x_prime_y64, 
                         matrix_gamma1_x_prime_y64_pointer + u_v_offset);
          matrix<uint64_t> matrix_v1_64(u, w);
          AssignToMatrix(matrix_v1_64, matrix_v1_64_pointer + u_w_offset);
          matrix<uint64_t> matrix_v2_64(u, w);
          AssignToMatrix(matrix_v2_64, matrix_v2_64_pointer + u_w_offset);
        
          matrix<uint64_t> w64 = 
            prod(matrix_v1_64 + matrix_v2_64, matrix_lambdas_y64_[i])
            - r64 * matrix_gammas_xy64_[i] + matrix_gamma1_x_prime_y64;
          AssignFromMatrix(matrix_w64_pointer + u_v_offset, w64);
          u_w_offset += u * w * sizeof(uint64_t);
          u_v_offset += u * v * sizeof(uint64_t);
        }
        assert(matrix_gamma1_x_prime_y64_offset + u_v_offset == matrix_gamma1_x_prime_y128_offset);
        assert(matrix_v64_offset + u_w_offset == matrix_v128_offset);
        assert(matrix_w64_offset + u_v_offset == matrix_w128_offset);
      }
      
      {
        uint8_t const* const matrix_gamma1_x_prime_y128_pointer = 
          randoms0.data() + matrix_gamma1_x_prime_y128_offset;
        uint8_t const* const matrix_v1_128_pointer = v1.data() + matrix_v128_offset;
        uint8_t const* const matrix_v2_128_pointer = v2.data() + matrix_v128_offset;
        uint8_t* const matrix_w128_pointer = w.data() + matrix_w128_offset;
        size_t u_w_offset = 0;
        size_t u_v_offset = 0;
        for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
          size_t const u = matrix_lambdas_x128_[i].size1();
          size_t const w = matrix_lambdas_x128_[i].size2();
          size_t const v = matrix_lambdas_y128_[i].size2();
          matrix<UInt128> matrix_gamma1_x_prime_y128(u, v);
          AssignToMatrix(matrix_gamma1_x_prime_y128, 
                         matrix_gamma1_x_prime_y128_pointer + u_v_offset);
          matrix<UInt128> matrix_v1_128(u, w);
          AssignToMatrix(matrix_v1_128, matrix_v1_128_pointer + u_w_offset);
          matrix<UInt128> matrix_v2_128(u, w);
          AssignToMatrix(matrix_v2_128, matrix_v2_128_pointer + u_w_offset);
        
          matrix<UInt128> w128 = 
            prod(matrix_v1_128 + matrix_v2_128, matrix_lambdas_y128_[i])
            - r128 * matrix_gammas_xy128_[i] + matrix_gamma1_x_prime_y128;
          AssignFromMatrix(matrix_w128_pointer + u_v_offset, w128);
          u_w_offset += u * w * sizeof(UInt128);
          u_v_offset += u * v * sizeof(UInt128);
        }
        assert(matrix_gamma1_x_prime_y128_offset + u_v_offset == randoms0.size());
        assert(matrix_v128_offset + u_w_offset == v_bytes);
        assert(matrix_w128_offset + u_v_offset == w_bytes);
      }
      
      uint8_t* hash_pointer = m.data() + v_bytes;
      assert((m.data() + m.size()) - hash_pointer == EVP_MAX_MD_SIZE);
      Blake2b(w.data(), hash_pointer, w.size());
      {
        auto message = communication::BuildMessage(kAuxiliatorVerifier, gate_id_, m);
        communication_layer.SendMessage(2, message.Release());
      }
      break;
      
    }
    case 2: {
      auto& rng0 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(0);
      auto& rng1 = backend_.GetBaseProvider().GetTheirRandomnessGenerator(1);
      //lambda2_xs are in randoms0
      std::vector<uint8_t> randoms0 = 
        rng0.template GetUnsigned<uint8_t>(gate_id_, lambda2_x_prime_bytes);
      //Only one random value shared between P1 and P2 is enough for the protocol
      UInt128 r128 = rng1.template GetUnsigned<UInt128>(gate_id_, 1)[0];
      uint64_t r64 = uint64_t(r128);

      //Calculate v2
      std::vector<uint8_t> v2(v_bytes);
      {
        uint8_t const* const lambda2_x_prime64_pointer = 
          randoms0.data() + lambda2_x_prime64_offset;
        uint8_t* const v2_64_pointer = v2.data() + v64_offset;
        size_t offset = 0;
        for(size_t i = 0; i != number_of_triples64; ++i) {
          uint64_t lambda2_x_prime64;
          memcpy(&lambda2_x_prime64, lambda2_x_prime64_pointer + offset, sizeof(uint64_t));
          uint64_t lambda2_x64 = lambdas_x64_[i];
        
          uint64_t v2_64 = r64 * lambda2_x64 - lambda2_x_prime64;
          memcpy(v2_64_pointer + offset, &v2_64, sizeof(uint64_t));
          offset += sizeof(uint64_t);
        }
      }
      
      {
        uint8_t const* const lambda2_x_prime128_pointer = 
          randoms0.data() + lambda2_x_prime128_offset;
        uint8_t* const v2_128_pointer = v2.data() + v128_offset;
        size_t offset = 0;
        for(size_t i = 0; i != number_of_triples128; ++i) {
          UInt128 lambda2_x_prime128;
          memcpy(&lambda2_x_prime128, lambda2_x_prime128_pointer + offset, sizeof(UInt128));
          UInt128 lambda2_x128 = lambdas_x128_[i];
        
          UInt128 v2_128 = r128 * lambda2_x128 - lambda2_x_prime128;
          memcpy(v2_128_pointer + offset, &v2_128, sizeof(UInt128));
          offset += sizeof(UInt128);
        }
      }
      
      {
        uint8_t const* const matrix_lambda2_x_prime64_pointer = 
          randoms0.data() + matrix_lambda2_x_prime64_offset;
        uint8_t* const matrix_v2_64_pointer = v2.data() + matrix_v64_offset;
        size_t u_w_offset = 0;
        for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
          size_t const u = matrix_lambdas_x64_[i].size1();
          size_t const w = matrix_lambdas_x64_[i].size2();
          matrix<uint64_t> matrix_lambda2_x_prime64(u, w);
          AssignToMatrix(matrix_lambda2_x_prime64, 
                         matrix_lambda2_x_prime64_pointer + u_w_offset);
        
          matrix<uint64_t> matrix_v2_64 = 
            r64 * matrix_lambdas_x64_[i] - matrix_lambda2_x_prime64;
          AssignFromMatrix(matrix_v2_64_pointer + u_w_offset, matrix_v2_64);
          u_w_offset += u * w * sizeof(uint64_t);
        }
      }
      
      {
        uint8_t const* const matrix_lambda2_x_prime128_pointer = 
          randoms0.data() + matrix_lambda2_x_prime128_offset;
        uint8_t* const matrix_v2_128_pointer = v2.data() + matrix_v128_offset;
        size_t u_w_offset = 0;
        for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
          size_t const u = matrix_lambdas_x128_[i].size1();
          size_t const w = matrix_lambdas_x128_[i].size2();
          matrix<UInt128> matrix_lambda2_x_prime128(u, w);
          AssignToMatrix(matrix_lambda2_x_prime128, 
                         matrix_lambda2_x_prime128_pointer + u_w_offset);
        
          matrix<UInt128> matrix_v2_128 = 
            r128 * matrix_lambdas_x128_[i] - matrix_lambda2_x_prime128;
          AssignFromMatrix(matrix_v2_128_pointer + u_w_offset, matrix_v2_128);
          u_w_offset += u * w * sizeof(UInt128);
        }
      }
      
      //Send v2
      {
        auto message = communication::BuildMessage(kAuxiliatorVerifier, gate_id_, v2);
        communication_layer.SendMessage(1, message.Release());
      }
      
      //Receive gamma2_x'y
      auto message = triple_future_p0_.get();
      auto payload = communication::GetMessage(message.data())->payload();
      std::span<uint8_t const> gammas2_x_prime_y{payload->Data(), payload->size()};
      assert(gammas2_x_prime_y.size() == gamma2_x_prime_bytes);
      //Receive (v1, hash(w))
      auto message_hash = triple_future_p1_p2_.get();
      auto payload_hash = communication::GetMessage(message_hash.data())->payload();
      //m contains v1 and the hash of w
      std::span<uint8_t const> m{payload_hash->Data(), payload_hash->size()};
      assert(m.size() == v_bytes + EVP_MAX_MD_SIZE);
      
      //Calculate w
      std::vector<uint8_t> w(w_bytes);
      {
        uint8_t const* const gamma2_x_prime_y64_pointer = 
          gammas2_x_prime_y.data() + gamma2_x_prime_y64_offset;
        uint8_t const* const v1_64_pointer = m.data() + v64_offset;
        uint8_t const* const v2_64_pointer = v2.data() + v64_offset;
        uint8_t* const w64_pointer = w.data() + w64_offset;
        size_t offset = 0;
        for(size_t i = 0; i != number_of_triples64; ++i) {
          uint64_t gamma2_x_prime_y64;
          memcpy(&gamma2_x_prime_y64, gamma2_x_prime_y64_pointer + offset, sizeof(uint64_t));
          uint64_t v1_64;
          memcpy(&v1_64, v1_64_pointer + offset, sizeof(uint64_t));
          uint64_t v2_64;
          memcpy(&v2_64, v2_64_pointer + offset, sizeof(uint64_t));
          uint64_t lambda2_y64 = lambdas_y64_[i];
          uint64_t gamma2_xy64 = gammas_xy64_[i];
        
          uint64_t v64 = v1_64 + v2_64;
          uint64_t w64 = -(v64 * lambda2_y64 - r64 * gamma2_xy64 + gamma2_x_prime_y64);
          memcpy(w64_pointer + offset, &w64, sizeof(uint64_t));
          offset += sizeof(uint64_t);
        }
      }
      
      {
        uint8_t const* const gamma2_x_prime_y128_pointer = 
          gammas2_x_prime_y.data() + gamma2_x_prime128_offset;
        uint8_t const* const v1_128_pointer = m.data() + v128_offset;
        uint8_t const* const v2_128_pointer = v2.data() + v128_offset;
        uint8_t* const w128_pointer = w.data() + w128_offset;
        size_t offset = 0;
        for(size_t i = 0; i != number_of_triples128; ++i) {
          UInt128 gamma2_x_prime_y128;
          memcpy(&gamma2_x_prime_y128, gamma2_x_prime_y128_pointer + offset, sizeof(UInt128));
          UInt128 v1_128;
          memcpy(&v1_128, v1_128_pointer + offset, sizeof(UInt128));
          UInt128 v2_128;
          memcpy(&v2_128, v2_128_pointer + offset, sizeof(UInt128));
          UInt128 lambda2_y128 = lambdas_y128_[i];
          UInt128 gamma2_xy128 = gammas_xy128_[i];
        
          UInt128 v128 = v1_128 + v2_128;
          UInt128 w128 = -(v128 * lambda2_y128 - r128 * gamma2_xy128 + gamma2_x_prime_y128);
          memcpy(w128_pointer + offset, &w128, sizeof(UInt128));
          offset += sizeof(UInt128);
        }
      }
      
      {
        uint8_t const* const matrix_gamma2_x_prime_y64_pointer = 
          gammas2_x_prime_y.data() + matrix_gamma2_x_prime_y64_offset;
        uint8_t const* const matrix_v1_64_pointer = m.data() + matrix_v64_offset;
        uint8_t const* const matrix_v2_64_pointer = v2.data() + matrix_v64_offset;
        uint8_t* const matrix_w64_pointer = w.data() + matrix_w64_offset;
        size_t u_w_offset = 0;
        size_t u_v_offset = 0;
        for(size_t i = 0; i != number_of_matrix_triples64; ++i) {
          size_t const u = matrix_lambdas_x64_[i].size1();
          size_t const w = matrix_lambdas_x64_[i].size2();
          size_t const v = matrix_lambdas_y64_[i].size2();
          matrix<uint64_t> matrix_gamma2_x_prime_y64(u, v);
          AssignToMatrix(matrix_gamma2_x_prime_y64, 
                         matrix_gamma2_x_prime_y64_pointer + u_v_offset);
          matrix<uint64_t> matrix_v1_64(u, w);
          AssignToMatrix(matrix_v1_64, matrix_v1_64_pointer + u_w_offset);
          matrix<uint64_t> matrix_v2_64(u, w);
          AssignToMatrix(matrix_v2_64, matrix_v2_64_pointer + u_w_offset);
        
          matrix<uint64_t> matrix_w64 = 
            -(prod(matrix_v1_64 + matrix_v2_64, matrix_lambdas_y64_[i])
              - r64 * matrix_gammas_xy64_[i] + matrix_gamma2_x_prime_y64);
          AssignFromMatrix(matrix_w64_pointer + u_v_offset, matrix_w64);
          u_w_offset += u * w * sizeof(uint64_t);
          u_v_offset += u * v * sizeof(uint64_t);
        }
      }
      
      {
        uint8_t const* const matrix_gamma2_x_prime_y128_pointer = 
          gammas2_x_prime_y.data() + matrix_gamma2_x_prime_y128_offset;
        uint8_t const* const matrix_v1_128_pointer = m.data() + matrix_v128_offset;
        uint8_t const* const matrix_v2_128_pointer = v2.data() + matrix_v128_offset;
        uint8_t* const matrix_w128_pointer = w.data() + matrix_w128_offset;
        size_t u_w_offset = 0;
        size_t u_v_offset = 0;
        for(size_t i = 0; i != number_of_matrix_triples128; ++i) {
          size_t const u = matrix_lambdas_x128_[i].size1();
          size_t const w = matrix_lambdas_x128_[i].size2();
          size_t const v = matrix_lambdas_y128_[i].size2();
          matrix<UInt128> matrix_gamma2_x_prime_y128(u, v);
          AssignToMatrix(matrix_gamma2_x_prime_y128, 
                         matrix_gamma2_x_prime_y128_pointer + u_v_offset);
          matrix<UInt128> matrix_v1_128(u, w);
          AssignToMatrix(matrix_v1_128, matrix_v1_128_pointer + u_w_offset);
          matrix<UInt128> matrix_v2_128(u, w);
          AssignToMatrix(matrix_v2_128, matrix_v2_128_pointer + u_w_offset);
        
          matrix<UInt128> matrix_w128 = 
            -(prod(matrix_v1_128 + matrix_v2_128, matrix_lambdas_y128_[i])
              - r128 * matrix_gammas_xy128_[i] + matrix_gamma2_x_prime_y128);
          AssignFromMatrix(matrix_w128_pointer + u_v_offset, matrix_w128);
          u_w_offset += u * w * sizeof(UInt128);
          u_v_offset += u * v * sizeof(UInt128);
        }
      }
      //Calculate hash and compare with received_hash
      std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
      Blake2b(w.data(), hash.data(), w.size());
      
      uint8_t const* const received_hash_pointer = m.data() + v_bytes;
      for(size_t i = 0; i != EVP_MAX_MD_SIZE; ++i) {
        if(hash[i] != received_hash_pointer[i]) {
          Abort();
        }
      }
    }
  }
}

}  // namespace encrypto::motion