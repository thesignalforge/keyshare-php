# Signalforge KeyShare (Pure PHP)

Pure PHP implementation of the `signalforge_keyshare` C extension - Shamir's Secret Sharing with authenticated envelopes.

## What This Package Replaces

This package is a drop-in replacement for the `signalforge_keyshare` PHP C extension. It provides identical API and behavior, allowing you to use the same code whether the C extension is installed or not.

## API Parity Guarantees

- **Function signatures**: Identical to C extension
- **Exception classes**: Same hierarchy and messages
- **Envelope format**: Binary-compatible with C extension
- **Deterministic output**: Same inputs produce identical shares
- **Authentication**: Same HMAC-SHA256 envelope format

## Requirements

- PHP 8.4+
- No external dependencies

## Installation

```bash
composer require signalforge/keyshare
```

## Quick Start

```php
<?php
use function Signalforge\KeyShare\share;
use function Signalforge\KeyShare\recover;

// Split a secret into 5 shares, requiring any 3 to reconstruct
$secret = "my sensitive data";
$shares = share($secret, 3, 5);

// Distribute shares to different parties
// $shares[1] -> Alice
// $shares[2] -> Bob
// $shares[3] -> Charlie

// Later: reconstruct with any 3 shares
$recovered = recover([
    1 => $shares[1],  // Alice
    3 => $shares[3],  // Charlie
    5 => $shares[5],  // Eve
]);

assert($recovered === $secret);
```

## API Reference

### share

```php
Signalforge\KeyShare\share(
    string $secret,
    int $threshold,
    int $shares
): array
```

Split a binary or UTF-8 secret into shares.

**Parameters:**
- `$secret` - The secret to split (1 to 65535 bytes)
- `$threshold` - Minimum shares needed to reconstruct (2 to 255)
- `$shares` - Total number of shares to generate (threshold to 255)

**Returns:** Associative array indexed by share number (1 to N) containing base64 encoded authenticated shares.

**Throws:** `Signalforge\KeyShare\Exception` on invalid parameters.

### recover

```php
Signalforge\KeyShare\recover(
    array $shares
): string
```

Reconstruct a secret from shares.

**Parameters:**
- `$shares` - Associative array of base64 encoded shares (minimum threshold count)

**Returns:** The original secret as a binary string.

**Throws:**
- `Signalforge\KeyShare\InsufficientSharesException` - Not enough shares to meet threshold
- `Signalforge\KeyShare\TamperingException` - MAC verification failure (tampering detected or mixed shares)
- `Signalforge\KeyShare\Exception` - Malformed envelope structure or other errors

### passphrase

```php
Signalforge\KeyShare\passphrase(
    string $passphrase,
    int $threshold,
    int $shares
): array
```

Derive a cryptographic key from a passphrase and split it into shares.

Uses PBKDF2-SHA256 with 100,000 iterations to derive a 32-byte key.

## Usage Examples

### Passphrase-Based Key Sharing

```php
use function Signalforge\KeyShare\passphrase;
use function Signalforge\KeyShare\recover;

// Split a passphrase-derived key among trustees
$shares = passphrase("correct horse battery staple", 3, 5);

// Recover the derived key (32 bytes)
$derivedKey = recover([
    2 => $shares[2],
    4 => $shares[4],
    5 => $shares[5],
]);

// Use the derived key for encryption
$ciphertext = openssl_encrypt($data, 'aes-256-gcm', $derivedKey, ...);
```

### Tamper Detection

```php
use function Signalforge\KeyShare\share;
use function Signalforge\KeyShare\recover;
use Signalforge\KeyShare\TamperingException;

$shares = share("secret", 2, 3);

// Tamper with a share
$tampered = $shares[1];
$decoded = base64_decode($tampered);
$decoded[10] = chr(ord($decoded[10]) ^ 0xFF);
$tampered = base64_encode($decoded);

try {
    recover([
        1 => $tampered,
        2 => $shares[2],
    ]);
} catch (TamperingException $e) {
    echo "Tampering detected: " . $e->getMessage();
}
```

## Share Format

Each share is a base64-encoded authenticated envelope:

```
+─────────+─────────────+───────────+─────────────+─────────+──────────+
│ Version │ Share Index │ Threshold │ Payload Len │ Payload │ Auth Tag │
│ 1 byte  │   1 byte    │  1 byte   │   2 bytes   │ N bytes │ 32 bytes │
+─────────+─────────────+───────────+─────────────+─────────+──────────+
```

The format is binary-compatible with the C extension.

## Performance Caveats vs C Extension

| Aspect | C Extension | Pure PHP |
|--------|-------------|----------|
| GF(256) ops | SIMD (AVX2/SSE2) | Scalar |
| Memory | Manual management | GC-managed |
| Key zeroing | `memset(_, 0, _)` | Unset only |
| Large secrets | Optimized batching | Per-byte loop |

### Performance Comparison

| Operation | C (AVX2) | PHP |
|-----------|----------|-----|
| share(32B, 5, 10) | ~10 μs | ~500 μs |
| recover(5 shares, 32B) | ~5 μs | ~300 μs |
| share(1KB, 5, 10) | ~65 μs | ~15 ms |

The pure PHP implementation is approximately 50-200x slower than the C extension with SIMD.

## When to Prefer the C Version

1. **Performance**: C extension is significantly faster
2. **Large secrets**: Memory efficiency for large data
3. **High throughput**: When splitting/recovering many secrets
4. **Production**: For security-critical applications

## When This Package is Sufficient

1. **Development**: Easier debugging without C extension
2. **Portability**: No compilation required
3. **Small secrets**: Keys, passwords, tokens
4. **Low volume**: Occasional secret sharing operations

## Security Considerations

### What This Provides

- **Information-theoretic security**: Fewer than threshold shares reveal nothing
- **Tamper detection**: HMAC-SHA256 on every share
- **Mix prevention**: Shares from different secrets cannot be combined

### What This Does Not Provide

- **Secure memory**: PHP cannot securely zero strings
- **Side-channel resistance**: Timing may leak information
- **Forward secrecy**: Compromising the secret compromises all shares

### Recommendations

1. Use the C extension in production
2. Keep shares confidential during transit/storage
3. Distribute shares through secure channels
4. Test recovery procedures before relying on them

## Testing

```bash
composer install
composer test
```

## License

MIT License - See LICENSE file
