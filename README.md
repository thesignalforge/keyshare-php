# Signalforge KeyShare

Shamir's Secret Sharing implementation in PHP with authenticated envelopes.

## Why Use Secret Sharing?

Secret sharing solves a fundamental problem: how do you protect a secret without creating a single point of failure?

**Use cases:**

- **Backup encryption keys** - Split your master key among family members or colleagues. No single person can access your data, but any 3 of 5 can recover it together.
- **Corporate secrets** - Require multiple executives to collaborate before accessing sensitive credentials.
- **Cryptocurrency wallets** - Distribute wallet recovery phrases so theft requires compromising multiple locations.
- **Dead man's switch** - Ensure trusted parties can recover access if you become unavailable.
- **Escrow systems** - Split credentials between parties who must cooperate.

The key insight: with a 3-of-5 scheme, an attacker must compromise 3 separate shares. Losing 2 shares doesn't matter - the remaining 3 still recover the secret perfectly.

## What is Shamir's Secret Sharing?

Shamir's Secret Sharing is a cryptographic algorithm invented by Adi Shamir in 1979. It splits a secret into multiple shares with two key properties:

1. **Threshold recovery** - Any `k` shares can reconstruct the secret
2. **Information-theoretic security** - Fewer than `k` shares reveal absolutely nothing about the secret (not even with unlimited computing power)

The algorithm works by encoding the secret as the constant term of a random polynomial of degree `k-1`. Each share is a point on this polynomial. With `k` points, you can uniquely determine the polynomial using Lagrange interpolation and recover the constant term (the secret).

## Installation

```bash
composer require signalforge/keyshare
```

**Requirements:** PHP 8.5+

## Usage

### Split a secret into shares

```php
use function Signalforge\KeyShare\share;
use function Signalforge\KeyShare\recover;

// Split a secret into 5 shares, requiring any 3 to reconstruct
$secret = "my database password";
$shares = share($secret, threshold: 3, shares: 5);

// Distribute shares to different parties/locations
// $shares[1] -> Store in password manager
// $shares[2] -> Give to Alice
// $shares[3] -> Give to Bob
// $shares[4] -> Store in safe deposit box
// $shares[5] -> Give to lawyer
```

### Recover the secret

```php
// Later: reconstruct with any 3 shares
$recovered = recover([
    1 => $shares[1],
    3 => $shares[3],
    5 => $shares[5],
]);

// $recovered === "my database password"
```

### Binary data

Works with any binary data, not just strings:

```php
$encryptionKey = random_bytes(32);
$shares = share($encryptionKey, 3, 5);
```

## API Reference

### share()

```php
function share(string $secret, int $threshold, int $shares): array
```

Split a secret into shares.

**Parameters:**
- `$secret` - The secret to split (1-65535 bytes)
- `$threshold` - Minimum shares needed to reconstruct (2-255)
- `$shares` - Total number of shares to generate (must be ≥ threshold, max 255)

**Returns:** Associative array indexed by share number (1 to N) containing base64-encoded authenticated shares.

### recover()

```php
function recover(array $shares): string
```

Reconstruct a secret from shares.

**Parameters:**
- `$shares` - Associative array of base64-encoded shares

**Returns:** The original secret.

**Throws:**
- `InsufficientSharesException` - Not enough shares provided
- `TamperingException` - Share tampering or mixing detected
- `Exception` - Invalid share format

## Security Features

### Tamper Detection

Each share includes an HMAC-SHA256 authentication tag. If a share is modified, recovery will fail with a `TamperingException`:

```php
use Signalforge\KeyShare\Exception\TamperingException;

try {
    $recovered = recover($shares);
} catch (TamperingException $e) {
    // Share was modified or shares from different secrets were mixed
}
```

### Mix Prevention

Shares from different secrets cannot be combined. The authentication ensures all shares originated from the same secret.

## Share Format

Each share is a base64-encoded authenticated envelope:

```
+─────────+─────────────+───────────+─────────────+─────────+──────────+
│ Version │ Share Index │ Threshold │ Payload Len │ Payload │ Auth Tag │
│ 1 byte  │   1 byte    │  1 byte   │   2 bytes   │ N bytes │ 32 bytes │
+─────────+─────────────+───────────+─────────────+─────────+──────────+
```

## Security Considerations

**What this provides:**
- Information-theoretic security (fewer than threshold shares reveal nothing)
- Tamper detection via HMAC-SHA256
- Prevention of mixing shares from different secrets

**What this does not provide:**
- Secure memory handling (PHP limitation)
- Side-channel resistance
- Protection against a compromised threshold of shareholders

**Recommendations:**
- Distribute shares through secure channels
- Store shares in separate physical/logical locations
- Test recovery procedures before relying on them
- Consider the trust model - who holds shares matters

## Testing

```bash
composer install
composer test
```

## License

MIT License
