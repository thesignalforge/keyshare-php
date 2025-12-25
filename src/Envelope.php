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
        return hash_hmac('sha256', self::AUTH_KEY_INFO, $secret, binary: true);
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

        // Build header using pack (C=unsigned char, n=unsigned short big-endian)
        $header = pack('CCCn', self::VERSION, $shareIndex, $threshold, $payloadLen);
        $data = $header . $payload;
        $tag = hash_hmac('sha256', $data, $authKey, binary: true);

        return $data . $tag;
    }

    /**
     * Parse envelope structure without MAC verification.
     *
     * @return array{index: int, threshold: int, payload: string}
     */
    public static function parse(string $envelope): array
    {
        $len = strlen($envelope);
        if ($len < self::MIN_SIZE) {
            throw new Exception('Envelope too short');
        }

        // Unpack header: version, index, threshold, payloadLen (big-endian)
        $header = unpack('Cversion/Cindex/Cthreshold/npayloadLen', $envelope);

        if ($header['version'] !== self::VERSION) {
            throw new Exception('Invalid envelope version');
        }

        $payloadLen = $header['payloadLen'];
        if ($len !== self::HEADER_SIZE + $payloadLen + self::TAG_SIZE) {
            throw new Exception('Envelope length mismatch');
        }

        return [
            'index' => $header['index'],
            'threshold' => $header['threshold'],
            'payload' => substr($envelope, self::HEADER_SIZE, $payloadLen),
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
        $len = strlen($envelope);
        if ($len < self::MIN_SIZE) {
            throw new Exception('Envelope too short');
        }

        // Unpack header: version, index, threshold, payloadLen (big-endian)
        $header = unpack('Cversion/Cindex/Cthreshold/npayloadLen', $envelope);

        if ($header['version'] !== self::VERSION) {
            throw new Exception('Invalid envelope version');
        }

        $payloadLen = $header['payloadLen'];
        $dataLen = self::HEADER_SIZE + $payloadLen;
        if ($len !== $dataLen + self::TAG_SIZE) {
            throw new Exception('Envelope length mismatch');
        }

        // Verify MAC
        $data = substr($envelope, 0, $dataLen);
        $storedTag = substr($envelope, $dataLen, self::TAG_SIZE);
        $expectedTag = hash_hmac('sha256', $data, $authKey, binary: true);

        if (!hash_equals($expectedTag, $storedTag)) {
            throw new TamperingException(
                'Share authentication failed: MAC mismatch (tampered or mixed shares)'
            );
        }

        return [
            'index' => $header['index'],
            'threshold' => $header['threshold'],
            'payload' => substr($envelope, self::HEADER_SIZE, $payloadLen),
        ];
    }
}
