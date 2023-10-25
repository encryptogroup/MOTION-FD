#pragma once

#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/io.hpp>

#include <cmath>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>

#include <fmt/format.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>

namespace program_options = boost::program_options;

std::pair<program_options::variables_map, bool> ParseProgramOptions(int ac, char* av[]);

// ASTRA
void Benchmark_MNIST_1(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_MNIST_2(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_MNIST_3(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_MNIST_4(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_MNIST_5(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_MNIST_6(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_MNIST_7(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_MNIST_8(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_MNIST_9(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_1(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_2(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_3(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_4(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_5(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_6(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_7(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_8(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_9(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_10(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_11(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_12(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_13(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_14(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_15(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_16(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_CIFAR_10_17(program_options::variables_map& user_options, size_t number_of_repetitions);

// Auxiliator
void Benchmark_Malicious_MNIST_1(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_MNIST_2(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_MNIST_3(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_MNIST_4(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_MNIST_5(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_MNIST_6(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_MNIST_7(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_MNIST_8(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_MNIST_9(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_1(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_2(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_3(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_4(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_5(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_6(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_7(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_8(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_9(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_10(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_11(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_12(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_13(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_14(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_15(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_16(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Malicious_CIFAR_10_17(program_options::variables_map& user_options, size_t number_of_repetitions);

// Socium
void Benchmark_Socium_MNIST_1(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_MNIST_2(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_MNIST_3(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_MNIST_4(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_MNIST_5(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_MNIST_6(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_MNIST_7(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_MNIST_8(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_MNIST_9(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_1(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_2(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_3(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_4(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_5(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_6(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_7(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_8(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_9(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_10(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_11(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_12(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_13(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_14(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_15(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_16(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Socium_CIFAR_10_17(program_options::variables_map& user_options, size_t number_of_repetitions);

// Swift
void Benchmark_Swift_MNIST_1(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_MNIST_2(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_MNIST_3(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_MNIST_4(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_MNIST_5(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_MNIST_6(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_MNIST_7(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_MNIST_8(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_MNIST_9(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_1(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_2(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_3(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_4(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_5(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_6(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_7(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_8(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_9(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_10(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_11(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_12(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_13(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_14(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_15(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_16(program_options::variables_map& user_options, size_t number_of_repetitions);
void Benchmark_Swift_CIFAR_10_17(program_options::variables_map& user_options, size_t number_of_repetitions);
