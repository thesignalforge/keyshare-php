<?php

declare(strict_types=1);

namespace Signalforge\KeyShare;

/**
 * GF(256) Galois Field arithmetic using log/exp tables.
 *
 * Uses the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
 * with generator 2, which generates all 255 non-zero elements.
 */

/** @var array<int>|null Log table for GF(256) multiplication */
$GLOBALS['__gf256_log'] = null;

/** @var array<int>|null Exp table for GF(256) multiplication */
$GLOBALS['__gf256_exp'] = null;

/**
 * Initialize log/exp tables.
 */
function gf256_init(): void
{
    if ($GLOBALS['__gf256_log'] !== null) {
        return;
    }

    $GLOBALS['__gf256_log'] = array_fill(0, 256, 0);
    $GLOBALS['__gf256_exp'] = array_fill(0, 512, 0);

    // Generate tables using the irreducible polynomial x^8 + x^4 + x^3 + x + 1
    $x = 1;
    for ($i = 0; $i < 255; $i++) {
        $GLOBALS['__gf256_exp'][$i] = $x;
        $GLOBALS['__gf256_log'][$x] = $i;

        // Multiply by generator (primitive element 2)
        // Using polynomial x^8 + x^4 + x^3 + x^2 + 1 where 2 is primitive
        // When overflow: x^8 = x^4 + x^3 + x^2 + 1 = 0x1D
        $x = (($x << 1) ^ (($x & 0x80) ? 0x1D : 0)) & 0xFF;
    }

    // Extend exp table for easier modular reduction
    for ($i = 255; $i < 512; $i++) {
        $GLOBALS['__gf256_exp'][$i] = $GLOBALS['__gf256_exp'][$i - 255];
    }

    // LOG[0] is undefined, set to 0 (multiply by 0 returns 0)
    $GLOBALS['__gf256_log'][0] = 0;
}

/**
 * Add two field elements.
 * In GF(2^n), addition is XOR.
 */
function gf256_add(int $a, int $b): int
{
    return $a ^ $b;
}

/**
 * Subtract two field elements.
 * In GF(2^n), subtraction is also XOR.
 */
function gf256_sub(int $a, int $b): int
{
    return $a ^ $b;
}

/**
 * Multiply two field elements.
 */
function gf256_mul(int $a, int $b): int
{
    gf256_init();

    if ($a === 0 || $b === 0) {
        return 0;
    }

    return $GLOBALS['__gf256_exp'][$GLOBALS['__gf256_log'][$a] + $GLOBALS['__gf256_log'][$b]];
}

/**
 * Divide two field elements.
 */
function gf256_div(int $a, int $b): int
{
    gf256_init();

    if ($b === 0) {
        throw new Exception('Division by zero in GF(256)');
    }

    if ($a === 0) {
        return 0;
    }

    return $GLOBALS['__gf256_exp'][($GLOBALS['__gf256_log'][$a] - $GLOBALS['__gf256_log'][$b] + 255) % 255];
}

/**
 * Compute multiplicative inverse.
 */
function gf256_inv(int $a): int
{
    gf256_init();

    if ($a === 0) {
        throw new Exception('Inverse of zero in GF(256)');
    }

    return $GLOBALS['__gf256_exp'][255 - $GLOBALS['__gf256_log'][$a]];
}

/**
 * Evaluate polynomial at x using Horner's method.
 *
 * coeffs[0] is constant term, coeffs[n] is x^n coefficient.
 *
 * @param array<int> $coeffs Polynomial coefficients
 * @param int $x Point to evaluate at
 * @return int Result
 */
function gf256_eval_poly(array $coeffs, int $x): int
{
    $result = 0;
    for ($i = count($coeffs) - 1; $i >= 0; $i--) {
        $result = gf256_add(gf256_mul($result, $x), $coeffs[$i]);
    }
    return $result;
}

/**
 * Compute Lagrange basis polynomial l_i(0).
 *
 * l_i(0) = product_{j!=i} (0 - x_j) / (x_i - x_j)
 *        = product_{j!=i} x_j / (x_i ^ x_j)  [in GF(256)]
 *
 * @param int $i Index in indices array
 * @param array<int> $indices Share indices
 * @return int Basis value
 */
function gf256_lagrange_basis(int $i, array $indices): int
{
    $xi = $indices[$i];
    $num = 1;
    $den = 1;
    $k = count($indices);

    for ($j = 0; $j < $k; $j++) {
        if ($j === $i) {
            continue;
        }
        $xj = $indices[$j];
        $num = gf256_mul($num, $xj);
        $den = gf256_mul($den, gf256_sub($xi, $xj));
    }

    return gf256_div($num, $den);
}
