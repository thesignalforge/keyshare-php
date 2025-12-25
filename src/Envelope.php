<?php

declare(strict_types=1);

namespace Signalforge\KeyShare;

use Signalforge\KeyShare\Exception\Exception;
use Signalforge\KeyShare\Exception\TamperingException;

/**
 * Authenticated share envelope format.
 *
 * Format:
 * +─────────+─────────────+───────────+─────────────+─────────+──────────+
 * │ Version │ Share Index │ Threshold │ Payload Len │ Payload │ Auth Tag │
 * │ 1 byte  │   1 byte    │  1 byte   │   2 bytes   │ N bytes │ 32 bytes │
 * +─────────+─────────────+───────────+─────────────+─────────+──────────+
 *
 * @internal
 */
final class Envelope
{
    public const VERSION = 1;
    public const HEADER_SIZE = 5;  // version + index + threshold + 2-byte length
    public const TAG_SIZE = 32;    // HMAC-SHA256 output
    public const MIN_SIZE = self::HEADER_SIZE + self::TAG_SIZE;

    private const AUTH_KEY_INFO = "signalforge-keyshare-auth-v1\x01";

    /**
     * Derive authentication key from secret.
     */
    public static function deriveAuthKey(string $secret): string
    {
        return hash_hmac('sha256', self::AUTH_KEY_INFO, $secret, true);
    }

    /**
     * Calculate envelope size for a payload.
     */
    public static function size(int $payloadLen): int
    {
        return self::HEADER_SIZE + $payloadLen + self::TAG_SIZE;
    }

    /**
     * Create an authenticated envelope.
     *
     * @return string Binary envelope data
     */
    public static function create(
        int $shareIndex,
        int $threshold,
        string $payload,
        string $authKey
    ): string {
        $payloadLen = strlen($payload);

        if ($payloadLen > 65535) {
            throw new Exception('Payload too large for envelope');
        }

        // Build header
        $header = chr(self::VERSION) .
                  chr($shareIndex) .
                  chr($threshold) .
                  chr(($payloadLen >> 8) & 0xFF) .
                  chr($payloadLen & 0xFF);

        // Compute auth tag over header + payload
        $tag = hash_hmac('sha256', $header . $payload, $authKey, true);

        return $header . $payload . $tag;
    }

    /**
     * Parse envelope structure without MAC verification.
     *
     * @return array{index: int, threshold: int, payload: string}
     */
    public static function parse(string $envelope): array
    {
        if (strlen($envelope) < self::MIN_SIZE) {
            throw new Exception('Envelope too short');
        }

        $version = ord($envelope[0]);
        if ($version !== self::VERSION) {
            throw new Exception('Invalid envelope version');
        }

        $index = ord($envelope[1]);
        $threshold = ord($envelope[2]);
        $payloadLen = (ord($envelope[3]) << 8) | ord($envelope[4]);

        $expectedLen = self::size($payloadLen);
        if (strlen($envelope) !== $expectedLen) {
            throw new Exception('Envelope length mismatch');
        }

        $payload = substr($envelope, self::HEADER_SIZE, $payloadLen);

        return [
            'index' => $index,
            'threshold' => $threshold,
            'payload' => $payload,
        ];
    }

    /**
     * Verify and parse an authenticated envelope.
     *
     * @return array{index: int, threshold: int, payload: string}
     * @throws TamperingException if MAC verification fails
     */
    public static function verify(string $envelope, string $authKey): array
    {
        if (strlen($envelope) < self::MIN_SIZE) {
            throw new Exception('Envelope too short');
        }

        $version = ord($envelope[0]);
        if ($version !== self::VERSION) {
            throw new Exception('Invalid envelope version');
        }

        $index = ord($envelope[1]);
        $threshold = ord($envelope[2]);
        $payloadLen = (ord($envelope[3]) << 8) | ord($envelope[4]);

        $expectedLen = self::size($payloadLen);
        if (strlen($envelope) !== $expectedLen) {
            throw new Exception('Envelope length mismatch');
        }

        $header = substr($envelope, 0, self::HEADER_SIZE);
        $payload = substr($envelope, self::HEADER_SIZE, $payloadLen);
        $storedTag = substr($envelope, self::HEADER_SIZE + $payloadLen, self::TAG_SIZE);

        // Compute expected tag
        $expectedTag = hash_hmac('sha256', $header . $payload, $authKey, true);

        // Constant-time comparison
        if (!hash_equals($expectedTag, $storedTag)) {
            throw new TamperingException(
                'Share authentication failed: MAC mismatch (tampered or mixed shares)'
            );
        }

        return [
            'index' => $index,
            'threshold' => $threshold,
            'payload' => $payload,
        ];
    }
}
