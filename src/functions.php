<?php

declare(strict_types=1);

namespace Signalforge\KeyShare;

use Signalforge\KeyShare\Exception\Exception;
use Signalforge\KeyShare\Exception\InsufficientSharesException;
use Signalforge\KeyShare\Exception\TamperingException;

/**
 * Split a secret into shares using Shamir's Secret Sharing.
 *
 * @param string $secret The secret to split (1-65535 bytes)
 * @param int $threshold Minimum shares needed to reconstruct (2-255)
 * @param int $shares Total number of shares to generate (threshold-255)
 * @return array<int, string> Associative array indexed by share number (1 to N), base64 encoded
 * @throws Exception on invalid parameters
 */
function share(string $secret, int $threshold, int $shares): array
{
    if ($threshold < 2 || $threshold > 255) {
        throw new Exception('Threshold must be between 2 and 255');
    }

    if ($shares < $threshold || $shares > 255) {
        throw new Exception('Number of shares must be >= threshold and <= 255');
    }

    if (strlen($secret) === 0) {
        throw new Exception('Secret cannot be empty');
    }

    if (strlen($secret) > Shamir::MAX_SECRET_LEN) {
        throw new Exception('Secret too long (max 65535 bytes)');
    }

    // Derive authentication key from secret
    $authKey = Envelope::deriveAuthKey($secret);

    // Generate deterministic seed from secret
    $seed = hash('sha256', $secret, true);

    // Split the secret
    $rawShares = Shamir::split($secret, $threshold, $shares, $seed);

    // Wrap each share in an authenticated envelope
    $result = [];
    foreach ($rawShares as $index => $shareData) {
        $envelope = Envelope::create($index, $threshold, $shareData, $authKey);
        $result[$index] = base64_encode($envelope);
    }

    return $result;
}

/**
 * Reconstruct a secret from shares.
 *
 * @param array<int, string> $shares Associative array of base64 encoded shares
 * @return string The original secret
 * @throws InsufficientSharesException if not enough shares
 * @throws TamperingException if MAC verification fails
 * @throws Exception on other errors
 */
function recover(array $shares): string
{
    if (count($shares) < 2) {
        throw new Exception('At least 2 shares are required');
    }

    if (count($shares) > 255) {
        throw new Exception('Too many shares (max 255)');
    }

    // First pass: decode shares without MAC verification
    $indices = [];
    $shareData = [];
    $rawShares = [];
    $firstThreshold = null;
    $shareLen = null;

    foreach ($shares as $key => $encoded) {
        if (!is_string($encoded)) {
            throw new Exception('All shares must be strings');
        }

        $decoded = base64_decode($encoded, true);
        if ($decoded === false) {
            throw new Exception('Invalid base64 in share');
        }

        $rawShares[$key] = $decoded;

        // Parse envelope structure
        $parsed = Envelope::parse($decoded);

        $indices[] = $parsed['index'];
        $shareData[] = $parsed['payload'];

        // Check threshold consistency
        if ($firstThreshold === null) {
            $firstThreshold = $parsed['threshold'];
            $shareLen = strlen($parsed['payload']);
        } else {
            if ($parsed['threshold'] !== $firstThreshold) {
                throw new Exception('Shares have mismatched thresholds');
            }
            if (strlen($parsed['payload']) !== $shareLen) {
                throw new Exception('Shares have mismatched lengths');
            }
        }
    }

    // Check we have enough shares
    if (count($shares) < $firstThreshold) {
        throw new InsufficientSharesException(
            'Insufficient shares for recovery (need more shares to meet threshold)'
        );
    }

    // Recover the secret using Lagrange interpolation
    $shareMap = [];
    foreach ($indices as $i => $index) {
        $shareMap[$index] = $shareData[$i];
    }
    $secret = Shamir::recover($shareMap);

    // Derive auth key from recovered secret
    $authKey = Envelope::deriveAuthKey($secret);

    // Second pass: verify all share MACs
    foreach ($rawShares as $decoded) {
        // This will throw TamperingException if MAC verification fails
        Envelope::verify($decoded, $authKey);
    }

    return $secret;
}
