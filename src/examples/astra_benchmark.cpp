#include "DEtI_benchmarks.h"

#include <iostream>
#include <string>

int main(int ac, char* av[]) {
  using namespace std::string_literals;
  auto [user_options, help_flag] = ParseProgramOptions(ac, av);
  // if help flag is set - print allowed command line arguments and exit
  if (help_flag) return EXIT_SUCCESS;

  std::string cnn = user_options["cnn"].as<std::string>();
  if (cnn != "mnist" && cnn != "cifar10") {
    throw std::runtime_error("Unknown CNN");
  }
  std::cout << "Running benchmarks on cnn " << cnn << std::endl;

  std::ofstream file;
  file.open("Astra_Benchmark_"s + cnn + "_P"s + std::to_string(user_options["my-id"].as<std::size_t>()) + ".txt"s);
  assert(file.is_open());
  std::streambuf* sbuf = std::cout.rdbuf();
  std::streambuf* fbuf = file.rdbuf();
  std::cout.rdbuf(fbuf);

  const auto number_of_repetitions = user_options["repetitions"].as<std::size_t>();
  
  if (cnn == "mnist") {
    Benchmark_MNIST_1(user_options, number_of_repetitions);
    Benchmark_MNIST_2(user_options, number_of_repetitions);
    Benchmark_MNIST_3(user_options, number_of_repetitions);
    Benchmark_MNIST_4(user_options, number_of_repetitions);
    Benchmark_MNIST_5(user_options, number_of_repetitions);
    Benchmark_MNIST_6(user_options, number_of_repetitions);
    Benchmark_MNIST_7(user_options, number_of_repetitions);
    Benchmark_MNIST_8(user_options, number_of_repetitions);
    Benchmark_MNIST_9(user_options, number_of_repetitions);
  } else if (cnn == "cifar10") {
    Benchmark_CIFAR_10_1(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_2(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_3(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_4(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_5(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_6(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_7(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_8(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_9(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_10(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_11(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_12(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_13(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_14(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_15(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_16(user_options, number_of_repetitions);
    Benchmark_CIFAR_10_17(user_options, number_of_repetitions);
  }
  
  std::cout << "\n\n" << std::endl;
  std::cout.rdbuf(sbuf);
  return EXIT_SUCCESS;
}
