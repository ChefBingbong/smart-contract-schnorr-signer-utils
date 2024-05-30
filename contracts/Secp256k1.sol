pragma solidity ^0.8.6;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

// this is a custom adapted implementation of the Scep256k1 curve based on the
// implementation at https://github.com/androlo/standard-contracts/blob/master/contracts/src/crypto/Secp256k1.sol
// my version includes some custom functions and extra matricx operations for ease of living. this code is not audited
library Secp256k1 {
    uint constant P = 2 ** 256 - 2 ** 32 - 977;
    uint constant PP =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint constant N =
        115792089237316195423570985008687907852837564279074904382605163141518161494337;
    uint256 constant A = 0;
    uint256 constant B = 7;
    uint256 constant Gx =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 constant Gy =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 private constant U255_MAX_PLUS_1 =
        57896044618658097711785492504343953926634992332820282019728792003956564819968;

    struct Point {
        uint256 x;
        uint256 y;
    }

    function jacAdd(
        uint256 _x1,
        uint256 _y1,
        uint256 _z1,
        uint256 _x2,
        uint256 _y2,
        uint256 _z2,
        uint256 _pp
    ) internal pure returns (uint256, uint256, uint256) {
        if (_x1 == 0 && _y1 == 0) return (_x2, _y2, _z2);
        if (_x2 == 0 && _y2 == 0) return (_x1, _y1, _z1);

        // We follow the equations described in https://pdfs.semanticscholar.org/5c64/29952e08025a9649c2b0ba32518e9a7fb5c2.pdf Section 5
        uint[4] memory zs; // z1^2, z1^3, z2^2, z2^3
        zs[0] = mulmod(_z1, _z1, _pp);
        zs[1] = mulmod(_z1, zs[0], _pp);
        zs[2] = mulmod(_z2, _z2, _pp);
        zs[3] = mulmod(_z2, zs[2], _pp);

        // u1, s1, u2, s2
        zs = [
            mulmod(_x1, zs[2], _pp),
            mulmod(_y1, zs[3], _pp),
            mulmod(_x2, zs[0], _pp),
            mulmod(_y2, zs[1], _pp)
        ];

        // In case of zs[0] == zs[2] && zs[1] == zs[3], double function should be used
        require(
            zs[0] != zs[2] || zs[1] != zs[3],
            "Use jacDouble function instead"
        );

        uint[4] memory hr;
        //h
        hr[0] = addmod(zs[2], _pp - zs[0], _pp);
        //r
        hr[1] = addmod(zs[3], _pp - zs[1], _pp);
        //h^2
        hr[2] = mulmod(hr[0], hr[0], _pp);
        // h^3
        hr[3] = mulmod(hr[2], hr[0], _pp);
        // qx = -h^3  -2u1h^2+r^2
        uint256 qx = addmod(mulmod(hr[1], hr[1], _pp), _pp - hr[3], _pp);
        qx = addmod(qx, _pp - mulmod(2, mulmod(zs[0], hr[2], _pp), _pp), _pp);
        // qy = -s1*z1*h^3+r(u1*h^2 -x^3)
        uint256 qy = mulmod(
            hr[1],
            addmod(mulmod(zs[0], hr[2], _pp), _pp - qx, _pp),
            _pp
        );
        qy = addmod(qy, _pp - mulmod(zs[1], hr[3], _pp), _pp);
        // qz = h*z1*z2
        uint256 qz = mulmod(hr[0], mulmod(_z1, _z2, _pp), _pp);
        return (qx, qy, qz);
    }

    function jacobianAdd(
        Point memory p,
        uint256 z1,
        Point memory q,
        uint256 z2
    ) internal pure returns (Point memory, uint256) {
        if (p.y == 0) return (q, z2);
        if (q.y == 0) return (p, z1);
        uint256 U1 = mulmod(p.x, mulmod(z2, z2, P), P);
        uint256 U2 = mulmod(q.x, mulmod(z1, z1, P), P);
        uint256 S1 = mulmod(p.y, mulmod(z2, mulmod(z2, z2, P), P), P);
        uint256 S2 = mulmod(q.y, mulmod(z1, mulmod(z1, z1, P), P), P);
        if (U1 == U2) {
            if (S1 != S2) return (Point(0, 0), 1);
            return jacobianDouble(p, z1);
        }
        uint256 H = addmod(U2, P - U1, P);
        uint256 R = addmod(S2, P - S1, P);
        uint256 H2 = mulmod(H, H, P);
        uint256 H3 = mulmod(H, H2, P);
        uint256 U1H2 = mulmod(U1, H2, P);
        uint256 nx = addmod(mulmod(R, R, P), P - H3, P);
        nx = addmod(nx, P - mulmod(2, U1H2, P), P);
        uint256 ny = addmod(
            mulmod(R, addmod(U1H2, P - nx, P), P),
            P - mulmod(S1, H3, P),
            P
        );
        uint256 nz = mulmod(H, mulmod(z1, z2, P), P);
        return (Point(nx, ny), nz);
    }

    function jacDouble(
        uint256 _x,
        uint256 _y,
        uint256 _z,
        uint256 _aa,
        uint256 _pp
    ) internal pure returns (uint256, uint256, uint256) {
        if (_z == 0) return (_x, _y, _z);

        // We follow the equations described in https://pdfs.semanticscholar.org/5c64/29952e08025a9649c2b0ba32518e9a7fb5c2.pdf Section 5
        // Note: there is a bug in the paper regarding the m parameter, M=3*(x1^2)+a*(z1^4)
        // x, y, z at this point represent the squares of _x, _y, _z
        uint256 x = mulmod(_x, _x, _pp); //x1^2
        uint256 y = mulmod(_y, _y, _pp); //y1^2
        uint256 z = mulmod(_z, _z, _pp); //z1^2

        // s
        uint s = mulmod(4, mulmod(_x, y, _pp), _pp);
        // m
        uint m = addmod(
            mulmod(3, x, _pp),
            mulmod(_aa, mulmod(z, z, _pp), _pp),
            _pp
        );

        // x, y, z at this point will be reassigned and rather represent qx, qy, qz from the paper
        // This allows to reduce the gas cost and stack footprint of the algorithm
        // qx
        x = addmod(mulmod(m, m, _pp), _pp - addmod(s, s, _pp), _pp);
        // qy = -8*y1^4 + M(S-T)
        y = addmod(
            mulmod(m, addmod(s, _pp - x, _pp), _pp),
            _pp - mulmod(8, mulmod(y, y, _pp), _pp),
            _pp
        );
        // qz = 2*y1*z1
        z = mulmod(2, mulmod(_y, _z, _pp), _pp);

        return (x, y, z);
    }

    function jacobianDouble(
        Point memory p,
        uint256 z
    ) internal pure returns (Point memory, uint256) {
        if (p.y == 0) return (Point(0, 0), 0);
        uint256 ysq = mulmod(p.y, p.y, P);
        uint256 S = mulmod(4, mulmod(p.x, ysq, P), P);
        uint256 M = addmod(
            mulmod(3, mulmod(p.x, p.x, P), P),
            mulmod(A, mulmod(z, z, P), P),
            P
        );
        uint256 nx = addmod(mulmod(M, M, P), P - mulmod(2, S, P), P);
        uint256 ny = addmod(
            mulmod(M, addmod(S, P - nx, P), P),
            P - mulmod(8, mulmod(ysq, ysq, P), P),
            P
        );
        uint256 nz = mulmod(2, mulmod(p.y, z, P), P);
        return (Point(nx, ny), nz);
    }

    function jacMul(
        uint256 _d,
        uint256 _x,
        uint256 _y,
        uint256 _z,
        uint256 _aa,
        uint256 _pp
    ) internal pure returns (uint256, uint256, uint256) {
        // Early return in case that `_d == 0`
        if (_d == 0) {
            return (_x, _y, _z);
        }

        uint256 remaining = _d;
        uint256 qx = 0;
        uint256 qy = 0;
        uint256 qz = 1;

        // Double and add algorithm
        while (remaining != 0) {
            if ((remaining & 1) != 0) {
                (qx, qy, qz) = jacAdd(qx, qy, qz, _x, _y, _z, _pp);
            }
            remaining = remaining / 2;
            (_x, _y, _z) = jacDouble(_x, _y, _z, _aa, _pp);
        }
        return (qx, qy, qz);
    }

    function jacobianMultiply(
        Point memory p,
        uint256 z,
        uint256 d
    ) internal pure returns (Point memory, uint256) {
        if (p.y == 0 || d == 0) return (Point(0, 0), 1);
        if (d == 1) return (Point(p.x, p.y), z);

        if (d < 0 || d >= N) {
            return jacobianMultiply(p, z, d % N);
        }
        if (d % 2 == 0) {
            (Point memory xp, uint256 xz) = jacobianMultiply(p, z, d / 2);
            return jacobianDouble(xp, xz);
        }

        if (d % 2 == 1) {
            (Point memory xp, uint256 xz) = jacobianMultiply(p, z, d / 2);
            (Point memory dp, uint256 dz) = jacobianDouble(xp, xz);
            return jacobianAdd(dp, dz, p, z);
        }
        return (Point(p.x, p.y), z);
    }

    // point to scalar operations
    function ecInv(
        uint256 _x,
        uint256 _y,
        uint256 _pp
    ) internal pure returns (uint256, uint256) {
        return (_x, (_pp - _y) % _pp);
    }

    function ecAdd(
        uint256 _x1,
        uint256 _y1,
        uint256 _x2,
        uint256 _y2,
        uint256 _aa,
        uint256 _pp
    ) internal pure returns (uint256, uint256) {
        uint x = 0;
        uint y = 0;
        uint z = 0;

        // Double if x1==x2 else add
        if (_x1 == _x2) {
            // y1 = -y2 mod p
            if (addmod(_y1, _y2, _pp) == 0) {
                return (0, 0);
            } else {
                // P1 = P2
                (x, y, z) = jacDouble(_x1, _y1, 1, _aa, _pp);
            }
        } else {
            (x, y, z) = jacAdd(_x1, _y1, 1, _x2, _y2, 1, _pp);
        }
        // Get back to affine
        return toAffine(x, y, z, _pp);
    }

    function ecSub(
        uint256 _x1,
        uint256 _y1,
        uint256 _x2,
        uint256 _y2,
        uint256 _aa,
        uint256 _pp
    ) internal pure returns (uint256, uint256) {
        // invert square
        (uint256 x, uint256 y) = ecInv(_x2, _y2, _pp);
        // P1-square
        return ecAdd(_x1, _y1, x, y, _aa, _pp);
    }

    function ecMul(
        uint256 _k,
        uint256 _x,
        uint256 _y,
        uint256 _aa,
        uint256 _pp
    ) internal pure returns (uint256, uint256) {
        // Jacobian multiplication
        (uint256 x1, uint256 y1, uint256 z1) = jacMul(_k, _x, _y, 1, _aa, _pp);
        // Get back to affine
        return toAffine(x1, y1, z1, _pp);
    }

    function multiply(
        Point memory p,
        uint256 d
    ) internal pure returns (Point memory) {
        (Point memory jp, uint256 jz) = jacobianMultiply(p, 1, d);
        return fromJacobian(jp, jz);
    }

    function add(
        Point memory p,
        Point memory q
    ) internal pure returns (Point memory) {
        (Point memory xp, uint256 xq) = toJacobian(p);
        (Point memory yp, uint256 yq) = toJacobian(q);
        (Point memory jp, uint256 jz) = jacobianAdd(xp, xq, yp, yq);
        return fromJacobian(jp, jz);
    }

    // curve point operation methods for converting between 2D/3D point types
    function toJacobian(
        Point memory p
    ) internal pure returns (Point memory, uint256) {
        return (Point(p.x, p.y), 1);
    }

    function fromJacobian(
        Point memory p,
        uint256 z
    ) internal pure returns (Point memory) {
        uint256 zInv = invMod(z, P);
        uint256 zInv2 = mulmod(zInv, zInv, P);
        uint256 zInv3 = mulmod(zInv2, zInv, P);
        return Point(mulmod(p.x, zInv2, P), mulmod(p.y, zInv3, P));
    }

    function toAffine(
        uint256 _x,
        uint256 _y,
        uint256 _z,
        uint256 _pp
    ) internal pure returns (uint256, uint256) {
        uint256 zInv = invMod(_z, _pp);
        uint256 zInv2 = mulmod(zInv, zInv, _pp);
        uint256 x2 = mulmod(_x, zInv2, _pp);
        uint256 y2 = mulmod(_y, mulmod(zInv, zInv2, _pp), _pp);

        return (x2, y2);
    }

    function deriveY(
        uint8 _prefix,
        uint256 _x,
        uint256 _aa,
        uint256 _bb,
        uint256 _pp
    ) internal pure returns (uint256) {
        require(
            _prefix == 0x02 || _prefix == 0x03,
            "EllipticCurve:innvalid compressed EC point prefix"
        );

        // x^3 + ax + b
        uint256 y2 = addmod(
            mulmod(_x, mulmod(_x, _x, _pp), _pp),
            addmod(mulmod(_x, _aa, _pp), _bb, _pp),
            _pp
        );
        y2 = expMod(y2, (_pp + 1) / 4, _pp);
        // uint256 cmp = yBit ^ y_ & 1;
        uint256 y = (y2 + _prefix) % 2 == 0 ? y2 : _pp - y2;

        return y;
    }

    function isOnCurve(
        uint _x,
        uint _y,
        uint _aa,
        uint _bb,
        uint _pp
    ) internal pure returns (bool) {
        if (0 == _x || _x >= _pp || 0 == _y || _y >= _pp) {
            return false;
        }
        // y^2
        uint lhs = mulmod(_y, _y, _pp);
        // x^3
        uint rhs = mulmod(mulmod(_x, _x, _pp), _x, _pp);
        if (_aa != 0) {
            // x^3 + a*x
            rhs = addmod(rhs, mulmod(_x, _aa, _pp), _pp);
        }
        if (_bb != 0) {
            // x^3 + a*x + b
            rhs = addmod(rhs, _bb, _pp);
        }

        return lhs == rhs;
    }

    // special curve modulus operations for handling point subtraction and
    // exponential airthmetic operations
    function invMod(uint256 _x, uint256 _pp) internal pure returns (uint256) {
        require(_x != 0 && _x != _pp && _pp != 0, "Invalid number");
        uint256 q = 0;
        uint256 newT = 1;
        uint256 r = _pp;
        uint256 t;
        while (_x != 0) {
            t = r / _x;
            (q, newT) = (newT, addmod(q, (_pp - mulmod(t, newT, _pp)), _pp));
            (r, _x) = (_x, r - t * _x);
        }

        return q;
    }

    function modSqrt(uint256 a, uint256 p) internal pure returns (uint256) {
        if (a == 0) return 0;
        if (expMod(a, (p - 1) / 2, p) != 1) return 0;

        uint256 s = p - 1;
        uint256 e = 0;
        while (s % 2 == 0) {
            s /= 2;
            e++;
        }

        uint256 n = 2;
        while (expMod(n, (p - 1) / 2, p) != p - 1) {
            n++;
        }

        uint256 x = expMod(a, (s + 1) / 2, p);
        uint256 b = expMod(a, s, p);
        uint256 g = expMod(n, s, p);
        uint256 r = e;

        while (true) {
            uint256 t = b;
            uint256 m = 0;
            for (m = 0; m < r; m++) {
                if (t == 1) break;
                t = expMod(t, 2, p);
            }

            if (m == 0) return x;

            uint256 gs = expMod(g, 2 ** (r - m - 1), p);
            g = mulmod(gs, gs, p);
            x = mulmod(x, gs, p);
            b = mulmod(b, g, p);
            r = m;
        }
    }

    function expMod(
        uint256 _base,
        uint256 _exp,
        uint256 _pp
    ) internal pure returns (uint256) {
        require(_pp != 0, "EllipticCurve: modulus is zero");

        if (_base == 0) return 0;
        if (_exp == 0) return 1;

        uint256 r = 1;
        uint256 bit = U255_MAX_PLUS_1;
        assembly {
            for {

            } gt(bit, 0) {

            } {
                r := mulmod(
                    mulmod(r, r, _pp),
                    exp(_base, iszero(iszero(and(_exp, bit)))),
                    _pp
                )
                r := mulmod(
                    mulmod(r, r, _pp),
                    exp(_base, iszero(iszero(and(_exp, div(bit, 2))))),
                    _pp
                )
                r := mulmod(
                    mulmod(r, r, _pp),
                    exp(_base, iszero(iszero(and(_exp, div(bit, 4))))),
                    _pp
                )
                r := mulmod(
                    mulmod(r, r, _pp),
                    exp(_base, iszero(iszero(and(_exp, div(bit, 8))))),
                    _pp
                )
                bit := div(bit, 16)
            }
        }

        return r;
    }

    function point_hash(uint256[2] memory point) public pure returns (address) {
        return
            address(
                uint160(
                    uint256(keccak256(abi.encodePacked(point[0], point[1])))
                ) & 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            );
    }

    function hashToPoint(
        bytes32 hash
    ) public pure returns (uint256 x, uint256 y) {
        uint256 x_candidate = uint256(hash) % PP;

        while (true) {
            uint256 y_squared = addmod(
                mulmod(x_candidate, mulmod(x_candidate, x_candidate, PP), PP),
                B,
                PP
            );
            y = modSqrt(y_squared, PP);

            if (y != 0) {
                x = x_candidate;
                break;
            }

            x_candidate = addmod(x_candidate, 1, PP);
        }
    }

    function isPubKey(uint[2] memory p) internal pure returns (bool isPK) {
        isPK = isOnCurve(p[0], p[1], A, B, PP);
    }

    function compress(
        uint[2] memory p
    ) internal pure returns (uint8 yBit, uint x) {
        x = p[0];
        yBit = p[1] & 1 == 1 ? 1 : 0;
    }

    function decompress(
        uint8 yBit,
        uint256 x
    ) internal pure returns (uint256[2] memory point) {
        uint256 p = PP;
        uint256 y2 = addmod(mulmod(x, mulmod(x, x, p), p), 7, p);
        uint256 y_ = expMod(y2, (p + 1) / 4, PP);
        uint256 cmp = yBit ^ (y_ & 1);
        point[0] = x;
        point[1] = (cmp == 0) ? y_ : p - y_;
    }

    function deriveAddress(
        uint256[2] memory pubkey
    ) public pure returns (address) {
        bytes memory pubkeyBytes = abi.encodePacked(pubkey[0], pubkey[1]);
        bytes32 pubkeyHash = keccak256(pubkeyBytes);
        return address(uint160(uint256(pubkeyHash)));
    }
}
