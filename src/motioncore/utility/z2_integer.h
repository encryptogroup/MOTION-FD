// MIT License
//
// Copyright (c) 2019-2021 Oleksandr Tkachenko, Arianne Roselina Prananto
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
#pragma once
#include <iosfwd>

struct Z2Integer{
  Z2Integer() = default;
  
  Z2Integer(uint64_t value) : value(value) {}
  
  Z2Integer& operator+=(Z2Integer const& other) {
    value ^= other.value;
    return *this; 
  }
  Z2Integer& operator-=(Z2Integer const& other) {
    value ^= other.value;
    return *this; 
  }
  Z2Integer& operator*=(Z2Integer const& other) {
    value &= other.value;
    return *this; 
  }
  uint64_t value;
  static constexpr size_t kNumberOfZ2Values = sizeof(value) * CHAR_BIT;
};

inline Z2Integer operator+(Z2Integer a, Z2Integer const& b) {
  a += b;
  return a;
}

inline Z2Integer operator-(Z2Integer a, Z2Integer const& b) {
  a -= b;
  return a;
}

inline Z2Integer operator*(Z2Integer a, Z2Integer const& b) {
  a *= b;
  return a;
}

inline std::ostream& operator<<(std::ostream& os, Z2Integer z2) {
  return os << uint64_t(z2.value);
  
}