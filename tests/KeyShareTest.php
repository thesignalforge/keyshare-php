<?php

declare(strict_types=1);

namespace Signalforge\KeyShare\Tests;

use PHPUnit\Framework\TestCase;
use Signalforge\KeyShare\Exception;
use Signalforge\KeyShare\TamperingException;
use Signalforge\KeyShare\InsufficientSharesException;

use function Signalforge\KeyShare\share;
use function Signalforge\KeyShare\recover;
use function Signalforge\KeyShare\passphrase;

final class KeyShareTest extends TestCase
{
    public function testBasicShareAndRecover(): void
    {
        $secret = 'my sensitive data';
        $shares = share($secret, 3, 5);

        $this->assertCount(5, $shares);
        $this->assertArrayHasKey(1, $shares);
        $this->assertArrayHasKey(5, $shares);

        // Recover with exactly threshold shares
        $recovered = recover([
            1 => $shares[1],
            3 => $shares[3],
            5 => $shares[5],
        ]);

        $this->assertSame($secret, $recovered);
    }

    public function testRecoverWithMoreThanThreshold(): void
    {
        $secret = 'test secret';
        $shares = share($secret, 2, 5);

        // Recover with all shares
        $recovered = recover($shares);

        $this->assertSame($secret, $recovered);
    }

    public function testRecoverWithDifferentShareCombinations(): void
    {
        $secret = 'the quick brown fox';
        $shares = share($secret, 3, 5);

        // Try different combinations
        $combo1 = recover([1 => $shares[1], 2 => $shares[2], 3 => $shares[3]]);
        $combo2 = recover([2 => $shares[2], 4 => $shares[4], 5 => $shares[5]]);
        $combo3 = recover([1 => $shares[1], 3 => $shares[3], 5 => $shares[5]]);

        $this->assertSame($secret, $combo1);
        $this->assertSame($secret, $combo2);
        $this->assertSame($secret, $combo3);
    }

    public function testPassphraseKeyDerivation(): void
    {
        $passphrase = 'correct horse battery staple';
        $shares = passphrase($passphrase, 3, 5);

        $this->assertCount(5, $shares);

        // Recover the derived key
        $derivedKey = recover([
            2 => $shares[2],
            4 => $shares[4],
            5 => $shares[5],
        ]);

        // Key should be 32 bytes
        $this->assertSame(32, strlen($derivedKey));
    }

    public function testDeterministicOutput(): void
    {
        $secret = 'deterministic test';

        $shares1 = share($secret, 2, 3);
        $shares2 = share($secret, 2, 3);

        // Same secret should produce identical shares
        $this->assertSame($shares1, $shares2);
    }

    public function testBinaryData(): void
    {
        $secret = random_bytes(256);
        $shares = share($secret, 5, 10);

        $recovered = recover([
            1 => $shares[1],
            3 => $shares[3],
            5 => $shares[5],
            7 => $shares[7],
            9 => $shares[9],
        ]);

        $this->assertSame($secret, $recovered);
    }

    public function testMinimalShares(): void
    {
        $secret = 'minimal';
        $shares = share($secret, 2, 2);

        $this->assertCount(2, $shares);

        $recovered = recover($shares);
        $this->assertSame($secret, $recovered);
    }

    public function testLargeSecret(): void
    {
        $secret = str_repeat('A', 1024);
        $shares = share($secret, 3, 5);

        $recovered = recover([
            1 => $shares[1],
            2 => $shares[2],
            3 => $shares[3],
        ]);

        $this->assertSame($secret, $recovered);
    }

    public function testTamperingDetection(): void
    {
        $secret = 'tamper test';
        $shares = share($secret, 2, 3);

        // Tamper with a share
        $tampered = $shares[1];
        $decoded = base64_decode($tampered);
        $decoded[10] = chr(ord($decoded[10]) ^ 0xFF);
        $tampered = base64_encode($decoded);

        $this->expectException(TamperingException::class);
        $this->expectExceptionMessageMatches('/MAC mismatch/');

        recover([
            1 => $tampered,
            2 => $shares[2],
        ]);
    }

    public function testMixedSharesDetection(): void
    {
        $secret1 = 'secret one';
        $secret2 = 'secret two';

        $shares1 = share($secret1, 2, 3);
        $shares2 = share($secret2, 2, 3);

        // Try to combine shares from different secrets
        $this->expectException(TamperingException::class);

        recover([
            1 => $shares1[1],
            2 => $shares2[2],
        ]);
    }

    public function testInsufficientShares(): void
    {
        $secret = 'threshold test';
        $shares = share($secret, 5, 10);

        // Try with fewer than threshold shares
        $this->expectException(InsufficientSharesException::class);

        recover([
            1 => $shares[1],
            2 => $shares[2],
            3 => $shares[3],
        ]);
    }

    public function testInvalidThreshold(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Threshold/');

        share('secret', 1, 5);  // Threshold must be at least 2
    }

    public function testInvalidShareCount(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/shares/i');

        share('secret', 5, 3);  // Shares must be >= threshold
    }

    public function testEmptySecret(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/empty/');

        share('', 2, 3);
    }

    public function testInvalidBase64Share(): void
    {
        $secret = 'test';
        $shares = share($secret, 2, 3);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/base64/i');

        recover([
            1 => '!!!invalid-base64!!!',
            2 => $shares[2],
        ]);
    }

    public function testSharesWithUnicode(): void
    {
        $secret = "Hello, 世界! Привет мир!";
        $shares = share($secret, 2, 3);

        $recovered = recover([
            1 => $shares[1],
            3 => $shares[3],
        ]);

        $this->assertSame($secret, $recovered);
    }
}
