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
        $secretLen = $secret |> strlen(...);

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

        $prng = $seed
            |> hash('sha256', ..., binary: true)
            |> new DeterministicPRNG(...);

        // Generate coefficients for each byte position
        // coeffs[byte][degree] where coeffs[byte][0] = secret[byte]
        $coeffs = [];
        for ($i = 0; $i < $secretLen; $i++) {
            $coeffs[$i] = [$secret[$i] |> ord(...)];
            for ($c = 1; $c < $threshold; $c++) {
                $coeffs[$i][] = $prng->nextByte();
            }
        }

        // Evaluate polynomial at each share index (1..numShares)
        $shares = [];
        for ($s = 1; $s <= $numShares; $s++) {
            $share = '';
            for ($i = 0; $i < $secretLen; $i++) {
                $share .= GF256::evalPoly($coeffs[$i], $s) |> chr(...);
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
        $numShares = $shares |> count(...);

        if ($numShares < 2) {
            throw new Exception('At least 2 shares required');
        }

        GF256::init();

        $indices = $shares |> array_keys(...);
        $shareData = $shares |> array_values(...);
        $shareLen = $shareData[0] |> strlen(...);

        // Validate all shares have same length
        foreach ($shareData as $share) {
            if (($share |> strlen(...)) !== $shareLen) {
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
                $basis = GF256::lagrangeBasis($i, $indices);
                $shareByte = $shareData[$i][$byte] |> ord(...);
                $result = GF256::add($result, GF256::mul($shareByte, $basis));
            }
            $secret .= $result |> chr(...);
        }

        return $secret;
    }
}

/**
 * Deterministic PRNG using SHA-256 in counter mode.
 *
 * @internal
 */
final class DeterministicPRNG
{
    private int $counter = 0;
    private string $buffer = '';
    private int $bufferPos = 0;

    public function __construct(
        private readonly string $key
    ) {}

    public function nextByte(): int
    {
        if ($this->bufferPos >= ($this->buffer |> strlen(...))) {
            $this->refill();
        }
        return $this->buffer[$this->bufferPos++] |> ord(...);
    }

    private function refill(): void
    {
        $this->buffer = ($this->key . ($this->counter |> pack('J', ...)))
            |> hash('sha256', ..., binary: true);
        $this->bufferPos = 0;
        $this->counter++;
    }
}
