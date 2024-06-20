pragma solidity ^0.8.6;

contract Uint512 {
  struct uint512 {
    uint256 hi;
    uint256 lo;
  }

  function mul(uint512 memory x, uint512 memory y) internal pure returns (uint512 memory) {
    uint256 xh = x.hi;
    uint256 xl = x.lo;
    uint256 yh = y.hi;
    uint256 yl = y.lo;

    // Calculate the cross-products
    uint256 ll = xl * yl;
    uint256 lh = xl * yh;
    uint256 hl = xh * yl;
    uint256 hh = xh * yh;

    // Calculate the carryovers
    uint256 carry = (lh >> 128) + (hl >> 128) + (((lh & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) + (hl & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)) >> 128);
    uint256 lo = ll + ((lh & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) << 128) + ((hl & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) << 128);
    uint256 hi = hh + (lh >> 128) + (hl >> 128) + carry;

    // Handle carryover for low part
    if (lo < ll) {
      hi += 1;
    }

    return uint512(hi, lo);
  }

  function div(uint512 memory x, uint512 memory y) internal pure returns (uint512 memory) {
    require(y.hi != 0 || y.lo != 0, "Division by zero");

    uint512 memory result;
    uint512 memory remainder;

    for (uint256 i = 511; i >= 0; i--) {
      remainder = shl(remainder, 1);
      if (bit(x, i) == 1) {
        remainder.lo |= 1;
      }
      if (ge(remainder, y)) {
        remainder = sub(remainder, y);
        result = or(result, shl(uint512(0, 1), i));
      }
    }

    return result;
  }

  function bit(uint512 memory x, uint256 i) internal pure returns (uint8) {
    if (i < 256) {
      return uint8((x.lo >> i) & 1);
    } else {
      return uint8((x.hi >> (i - 256)) & 1);
    }
  }

  function shl(uint512 memory x, uint256 n) internal pure returns (uint512 memory) {
    if (n >= 256) {
      return uint512(x.lo << (n - 256), 0);
    } else {
      return uint512((x.hi << n) | (x.lo >> (256 - n)), x.lo << n);
    }
  }

  function ge(uint512 memory x, uint512 memory y) internal pure returns (bool) {
    if (x.hi > y.hi) {
      return true;
    } else if (x.hi < y.hi) {
      return false;
    } else {
      return x.lo >= y.lo;
    }
  }

  function sub(uint512 memory x, uint512 memory y) internal pure returns (uint512 memory) {
    uint256 hi = x.hi - y.hi;
    uint256 lo = x.lo - y.lo;
    if (x.lo < y.lo) {
      hi -= 1;
    }
    return uint512(hi, lo);
  }

  function or(uint512 memory x, uint512 memory y) internal pure returns (uint512 memory) {
    return uint512(x.hi | y.hi, x.lo | y.lo);
  }
}
