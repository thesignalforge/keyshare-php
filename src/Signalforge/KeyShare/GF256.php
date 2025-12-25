<?php

declare(strict_types=1);

namespace Signalforge\KeyShare;

/**
 * GF(256) Galois Field arithmetic using log/exp tables.
 *
 * Uses the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
 * with generator 2, which generates all 255 non-zero elements.
 *
 * @internal
 */
final class GF256
{
    /** Log table for GF(256) multiplication */
    private static array $LOG;

    /** Exp table for GF(256) multiplication */
    private static array $EXP;

    /** Whether tables are initialized */
    private static bool $initialized = false;

    /**
     * Initialize log/exp tables.
     */
    public static function init(): void
    {
        if (self::$initialized) {
            return;
        }

        self::$LOG = array_fill(0, 256, 0);
        self::$EXP = array_fill(0, 512, 0);

        // Generate tables using the irreducible polynomial x^8 + x^4 + x^3 + x + 1
        $x = 1;
        for ($i = 0; $i < 255; $i++) {
            self::$EXP[$i] = $x;
            self::$LOG[$x] = $i;

            // Multiply by generator (primitive element 2)
            // Using polynomial x^8 + x^4 + x^3 + x^2 + 1 where 2 is primitive
            // When overflow: x^8 = x^4 + x^3 + x^2 + 1 = 0x1D
            $x = (($x << 1) ^ (($x & 0x80) ? 0x1D : 0)) & 0xFF;
        }

        // Extend exp table for easier modular reduction
        for ($i = 255; $i < 512; $i++) {
            self::$EXP[$i] = self::$EXP[$i - 255];
        }

        // LOG[0] is undefined, set to 0 (multiply by 0 returns 0)
        self::$LOG[0] = 0;

        self::$initialized = true;
    }

    /**
     * Add two field elements.
     * In GF(2^n), addition is XOR.
     */
    public static function add(int $a, int $b): int
    {
        return $a ^ $b;
    }

    /**
     * Subtract two field elements.
     * In GF(2^n), subtraction is also XOR.
     */
    public static function sub(int $a, int $b): int
    {
        return $a ^ $b;
    }

    /**
     * Multiply two field elements.
     */
    public static function mul(int $a, int $b): int
    {
        self::init();

        if ($a === 0 || $b === 0) {
            return 0;
        }

        return self::$EXP[self::$LOG[$a] + self::$LOG[$b]];
    }

    /**
     * Divide two field elements.
     */
    public static function div(int $a, int $b): int
    {
        self::init();

        if ($b === 0) {
            throw new Exception('Division by zero in GF(256)');
        }

        if ($a === 0) {
            return 0;
        }

        return self::$EXP[(self::$LOG[$a] - self::$LOG[$b] + 255) % 255];
    }

    /**
     * Compute multiplicative inverse.
     */
    public static function inv(int $a): int
    {
        self::init();

        if ($a === 0) {
            throw new Exception('Inverse of zero in GF(256)');
        }

        return self::$EXP[255 - self::$LOG[$a]];
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
    public static function evalPoly(array $coeffs, int $x): int
    {
        $result = 0;
        for ($i = count($coeffs) - 1; $i >= 0; $i--) {
            $result = self::add(self::mul($result, $x), $coeffs[$i]);
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
    public static function lagrangeBasis(int $i, array $indices): int
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
            $num = self::mul($num, $xj);
            $den = self::mul($den, self::sub($xi, $xj));
        }

        return self::div($num, $den);
    }
}
