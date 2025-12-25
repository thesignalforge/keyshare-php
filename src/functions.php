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
    $secretLen = strlen($secret);

    if ($threshold < 2 || $threshold > 255) {
        throw new Exception('Threshold must be between 2 and 255');
    }

    if ($shares < $threshold || $shares > 255) {
        throw new Exception('Number of shares must be >= threshold and <= 255');
    }

    if ($secretLen === 0) {
        throw new Exception('Secret cannot be empty');
    }

    if ($secretLen > Shamir::MAX_SECRET_LEN) {
        throw new Exception('Secret too long (max 65535 bytes)');
    }

    $authKey = Envelope::deriveAuthKey($secret);
    $seed = hash('sha256', $secret, binary: true);
    $rawShares = Shamir::split($secret, $threshold, $shares, $seed);

    $result = [];
    foreach ($rawShares as $index => $shareData) {
        $result[$index] = base64_encode(Envelope::create($index, $threshold, $shareData, $authKey));
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
    $count = count($shares);

    if ($count < 2) {
        throw new Exception('At least 2 shares are required');
    }

    if ($count > 255) {
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

        $decoded = base64_decode($encoded, strict: true);
        if ($decoded === false) {
            throw new Exception('Invalid base64 in share');
        }

        $rawShares[$key] = $decoded;
        $parsed = Envelope::parse($decoded);

        $indices[] = $parsed['index'];
        $shareData[] = $parsed['payload'];

        // Check threshold consistency
        $payloadLen = strlen($parsed['payload']);
        if ($firstThreshold === null) {
            $firstThreshold = $parsed['threshold'];
            $shareLen = $payloadLen;
        } else {
            if ($parsed['threshold'] !== $firstThreshold) {
                throw new Exception('Shares have mismatched thresholds');
            }
            if ($payloadLen !== $shareLen) {
                throw new Exception('Shares have mismatched lengths');
            }
        }
    }

    // Check we have enough shares
    if ($count < $firstThreshold) {
        throw new InsufficientSharesException(
            'Insufficient shares for recovery (need more shares to meet threshold)'
        );
    }

    // Recover the secret using Lagrange interpolation
    $shareMap = array_combine($indices, $shareData);
    $secret = Shamir::recover($shareMap);

    // Derive auth key from recovered secret and verify all share MACs
    $authKey = Envelope::deriveAuthKey($secret);

    foreach ($rawShares as $decoded) {
        Envelope::verify($decoded, $authKey);
    }

    return $secret;
}
