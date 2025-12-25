<?php

declare(strict_types=1);

namespace Signalforge\KeyShare;

use Signalforge\KeyShare\Exception\Exception;

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

        GF256::init();

        $prng = new DeterministicPRNG(hash('sha256', $seed, binary: true));

        // Generate coefficients for each byte position
        // coeffs[byte][degree] where coeffs[byte][0] = secret[byte]
        $secretBytes = unpack('C*', $secret);
        $coeffs = [];
        for ($i = 1; $i <= $secretLen; $i++) {
            $coeffs[$i] = [$secretBytes[$i]];
            for ($c = 1; $c < $threshold; $c++) {
                $coeffs[$i][] = $prng->nextByte();
            }
        }

        // Evaluate polynomial at each share index (1..numShares)
        $shares = [];
        for ($s = 1; $s <= $numShares; $s++) {
            $shareBytes = [];
            for ($i = 1; $i <= $secretLen; $i++) {
                $shareBytes[] = GF256::evalPoly($coeffs[$i], $s);
            }
            $shares[$s] = pack('C*', ...$shareBytes);
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

        GF256::init();

        $indices = array_keys($shares);
        $shareData = array_values($shares);
        $shareLen = strlen($shareData[0]);

        // Validate all shares have same length
        foreach ($shareData as $share) {
            if (strlen($share) !== $shareLen) {
                throw new Exception('All shares must have the same length');
            }
        }

        // Validate indices and check for duplicates using a set
        $seen = [];
        foreach ($indices as $index) {
            if ($index < 1 || $index > 255) {
                throw new Exception('Invalid share index (must be 1-255)');
            }
            if (isset($seen[$index])) {
                throw new Exception('Duplicate share indices detected');
            }
            $seen[$index] = true;
        }

        // Precompute Lagrange basis values (independent of byte position)
        $basis = [];
        for ($i = 0; $i < $numShares; $i++) {
            $basis[$i] = GF256::lagrangeBasis($i, $indices);
        }

        // Preprocess share bytes to arrays for faster access
        $shareBytes = [];
        for ($i = 0; $i < $numShares; $i++) {
            $shareBytes[$i] = unpack('C*', $shareData[$i]);
        }

        // Lagrange interpolation at x=0
        $secretBytes = [];
        for ($byte = 1; $byte <= $shareLen; $byte++) {
            $result = 0;
            for ($i = 0; $i < $numShares; $i++) {
                // Inline: result ^= mul(shareBytes[i][byte], basis[i])
                $sb = $shareBytes[$i][$byte];
                if ($sb !== 0 && $basis[$i] !== 0) {
                    $result ^= GF256::mul($sb, $basis[$i]);
                }
            }
            $secretBytes[] = $result;
        }

        return pack('C*', ...$secretBytes);
    }
}

/**
 * Deterministic PRNG using SHA-256 in counter mode.
 *
 * @internal
 */
final class DeterministicPRNG
{
    private const BUFFER_SIZE = 32; // SHA-256 output size

    private int $counter = 0;
    private string $buffer = '';
    private int $bufferPos = 32; // Force initial refill

    public function __construct(
        private readonly string $key
    ) {}

    public function nextByte(): int
    {
        if ($this->bufferPos >= self::BUFFER_SIZE) {
            $this->buffer = hash('sha256', $this->key . pack('J', $this->counter++), binary: true);
            $this->bufferPos = 0;
        }
        return ord($this->buffer[$this->bufferPos++]);
    }
}
