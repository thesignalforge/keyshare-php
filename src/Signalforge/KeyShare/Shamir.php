<?php

declare(strict_types=1);

namespace Signalforge\KeyShare;

/**
 * Shamir's Secret Sharing implementation.
 *
 * Uses GF(256) arithmetic for byte-wise operations.
 * Polynomial coefficients are generated deterministically from a seed.
 *
 * @internal
 */
final class Shamir
{
    public const MAX_SECRET_LEN = 65535;

    /**
     * Split a secret into shares.
     *
     * @param string $secret The secret to split
     * @param int $threshold Minimum shares needed for recovery (2-255)
     * @param int $numShares Total number of shares (threshold-255)
     * @param string $seed Deterministic seed for coefficient generation
     * @return array<int, string> Shares indexed 1..numShares
     */
    public static function split(
        string $secret,
        int $threshold,
        int $numShares,
        string $seed
    ): array {
        $secretLen = strlen($secret);

        if ($threshold < 2 || $threshold > 255) {
            throw new Exception('Threshold must be between 2 and 255');
        }

        if ($numShares < $threshold || $numShares > 255) {
            throw new Exception('Number of shares must be >= threshold and <= 255');
        }

        if ($secretLen === 0 || $secretLen > self::MAX_SECRET_LEN) {
            throw new Exception('Secret length must be 1-65535 bytes');
        }

        // Initialize GF(256)
        GF256::init();

        // Initialize PRNG from seed
        $prng = new DeterministicPRNG(hash('sha256', $seed, true));

        // Generate coefficients for each byte position
        // coeffs[byte][degree] where coeffs[byte][0] = secret[byte]
        $coeffs = [];
        for ($i = 0; $i < $secretLen; $i++) {
            $coeffs[$i] = [ord($secret[$i])]; // Constant term is secret byte
            for ($c = 1; $c < $threshold; $c++) {
                $coeffs[$i][] = $prng->nextByte();
            }
        }

        // Evaluate polynomial at each share index (1..numShares)
        $shares = [];
        for ($s = 1; $s <= $numShares; $s++) {
            $share = '';
            for ($i = 0; $i < $secretLen; $i++) {
                $share .= chr(GF256::evalPoly($coeffs[$i], $s));
            }
            $shares[$s] = $share;
        }

        return $shares;
    }

    /**
     * Recover a secret from shares using Lagrange interpolation.
     *
     * @param array<int, string> $shares Shares indexed by share number (1-255)
     * @return string Recovered secret
     */
    public static function recover(array $shares): string
    {
        $numShares = count($shares);

        if ($numShares < 2) {
            throw new Exception('At least 2 shares required');
        }

        // Initialize GF(256)
        GF256::init();

        // Extract indices and validate
        $indices = array_keys($shares);
        $shareData = array_values($shares);
        $shareLen = strlen($shareData[0]);

        // Validate all shares have same length
        foreach ($shareData as $share) {
            if (strlen($share) !== $shareLen) {
                throw new Exception('All shares must have the same length');
            }
        }

        // Validate indices
        foreach ($indices as $i => $index) {
            if ($index < 1 || $index > 255) {
                throw new Exception('Invalid share index (must be 1-255)');
            }
            for ($j = $i + 1; $j < $numShares; $j++) {
                if ($indices[$j] === $index) {
                    throw new Exception('Duplicate share indices detected');
                }
            }
        }

        // Lagrange interpolation at x=0
        $secret = '';
        for ($byte = 0; $byte < $shareLen; $byte++) {
            $result = 0;
            for ($i = 0; $i < $numShares; $i++) {
                $basis = self::lagrangeBasis($i, $indices);
                $shareByte = ord($shareData[$i][$byte]);
                $result = GF256::add($result, GF256::mul($shareByte, $basis));
            }
            $secret .= chr($result);
        }

        return $secret;
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
    private static function lagrangeBasis(int $i, array $indices): int
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
            $num = GF256::mul($num, $xj);
            $den = GF256::mul($den, GF256::sub($xi, $xj));
        }

        return GF256::div($num, $den);
    }
}

/**
 * Deterministic PRNG using SHA-256 in counter mode.
 *
 * @internal
 */
final class DeterministicPRNG
{
    private string $key;
    private int $counter = 0;
    private string $buffer = '';
    private int $bufferPos = 0;

    public function __construct(string $key)
    {
        $this->key = $key;
    }

    public function nextByte(): int
    {
        if ($this->bufferPos >= strlen($this->buffer)) {
            $this->refill();
        }
        return ord($this->buffer[$this->bufferPos++]);
    }

    private function refill(): void
    {
        $counterBytes = pack('J', $this->counter); // 64-bit big-endian
        $this->buffer = hash('sha256', $this->key . $counterBytes, true);
        $this->bufferPos = 0;
        $this->counter++;
    }
}
