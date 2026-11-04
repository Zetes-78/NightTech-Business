using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NightTech.Business.Core.Sentinel;

/// <summary>
/// The cryptography Sentinel trusts. Everything uses NIST P-256, SHA-256 and AES-256-GCM, the same algorithms a web
/// browser's built-in WebCrypto offers, so the tech console can sign and encrypt without any add-on.
/// Public keys travel as base64 SubjectPublicKeyInfo (WebCrypto's "spki" export); signatures are the 64-byte r||s form
/// WebCrypto produces.
/// </summary>
public static class SentinelCrypto
{
    /// <summary>A short, readable name for a public key: the first 16 bytes of its SHA-256, in hex.</summary>
    public static string KeyId(string spkiBase64) =>
        Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(spkiBase64)))[..32].ToLowerInvariant();

    /// <summary>
    /// A PC's ID is worked out from its own public key, so a server can't give two PCs the same ID (which would let one
    /// signed command run on both) or swap a PC's key without the ID changing.
    /// </summary>
    public static string DeviceId(string spkiBase64) => "dev_" + KeyId(spkiBase64);

    /// <summary>Groups a key ID so a person can compare it by eye: "3f2a 91c0 ...".</summary>
    public static string Readable(string keyId) =>
        string.Join(' ', Enumerable.Range(0, keyId.Length / 4).Select(i => keyId.Substring(i * 4, 4)));

    public static ECDsa NewSigningKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public static string PublicKey(ECDsa key) => Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

    public static string Sign(ECDsa key, byte[] payload) =>
        Convert.ToBase64String(key.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

    /// <summary>Checks a signature against a public key. Any malformed input is simply "not valid".</summary>
    public static bool Verify(string spkiBase64, byte[] payload, string signatureBase64)
    {
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(spkiBase64), out _);
            if (key.KeySize != 256) return false;
            var sig = Convert.FromBase64String(signatureBase64);
            return sig.Length == 64 && key.VerifyData(payload, sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception e) when (e is FormatException or CryptographicException or ArgumentException) { return false; }
    }

    /// <summary>Random letters and digits for one-time codes and IDs (no look-alike characters).</summary>
    public static string RandomCode(int length)
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        return string.Create(length, 0, (span, _) =>
        {
            for (int i = 0; i < span.Length; i++) span[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        });
    }

    public static bool FixedTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}

/// <summary>
/// One encrypted remote session (remote shell or remote desktop) between the tech's browser and a client PC.
/// The server only passes the encrypted frames along: it never holds the keys, so it can't read or change a session.
/// <para>
/// Both sides make a fresh ECDH P-256 key pair for the session. The shared secret goes through HKDF-SHA256
/// (salt = SHA-256 of the session ID, info = "NightTech Sentinel session v1" + both public keys) to give one AES-256-GCM
/// key for each direction. Each frame's 12-byte nonce is 4 zero bytes and an 8-byte counter, and the receiver only
/// accepts counters that go up, so frames can't be replayed or reordered.
/// </para>
/// </summary>
public sealed class SessionCrypto : IDisposable
{
    public const string Info = "NightTech Sentinel session v1";
    private readonly AesGcm _send, _receive;
    private ulong _sendCounter;
    private ulong _lastReceived;
    private bool _receivedAny;
    private readonly object _sendLock = new();

    /// <param name="isAgent">The client PC's side (true) or the browser's (false); each side sends with its own key.</param>
    public SessionCrypto(ECDiffieHellman mine, string theirSpki, string sessionId, string browserSpki, string agentSpki, bool isAgent)
    {
        using var theirs = ECDiffieHellman.Create();
        theirs.ImportSubjectPublicKeyInfo(Convert.FromBase64String(theirSpki), out _);
        var shared = mine.DeriveRawSecretAgreement(theirs.PublicKey);
        var keys = DeriveKeys(shared, sessionId, browserSpki, agentSpki);
        CryptographicOperations.ZeroMemory(shared);
        var toAgent = keys.AsSpan(0, 32).ToArray();
        var toBrowser = keys.AsSpan(32, 32).ToArray();
        CryptographicOperations.ZeroMemory(keys);
        _send = new AesGcm(isAgent ? toBrowser : toAgent, 16);
        _receive = new AesGcm(isAgent ? toAgent : toBrowser, 16);
        CryptographicOperations.ZeroMemory(toAgent);
        CryptographicOperations.ZeroMemory(toBrowser);
    }

    public static byte[] DeriveKeys(byte[] shared, string sessionId, string browserSpki, string agentSpki)
    {
        var salt = SHA256.HashData(Encoding.UTF8.GetBytes(sessionId));
        var info = Encoding.UTF8.GetBytes(Info + "|" + browserSpki + "|" + agentSpki);
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 64, salt, info);
    }

    /// <summary>counter (8 bytes, big-endian) || ciphertext || tag (16 bytes).</summary>
    public byte[] Seal(ReadOnlySpan<byte> plain)
    {
        lock (_sendLock)
        {
            _sendCounter++;
            var frame = new byte[8 + plain.Length + 16];
            BinaryPrimitives.WriteUInt64BigEndian(frame, _sendCounter);
            _send.Encrypt(Nonce(_sendCounter), plain, frame.AsSpan(8, plain.Length), frame.AsSpan(8 + plain.Length, 16));
            return frame;
        }
    }

    /// <summary>Decrypts a frame. Throws CryptographicException for anything tampered with, replayed or out of order.</summary>
    public byte[] Open(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 24) throw new CryptographicException("Frame too short.");
        ulong counter = BinaryPrimitives.ReadUInt64BigEndian(frame);
        if (counter == 0 || _receivedAny && counter <= _lastReceived) throw new CryptographicException("Frame replayed or out of order.");
        var plain = new byte[frame.Length - 24];
        _receive.Decrypt(Nonce(counter), frame.Slice(8, plain.Length), frame.Slice(8 + plain.Length, 16), plain);
        _lastReceived = counter;
        _receivedAny = true;
        return plain;
    }

    private static byte[] Nonce(ulong counter)
    {
        var n = new byte[12];
        BinaryPrimitives.WriteUInt64BigEndian(n.AsSpan(4), counter);
        return n;
    }

    public void Dispose()
    {
        _send.Dispose();
        _receive.Dispose();
    }
}

/// <summary>Two-step sign-in codes for the tech console (RFC 6238, the codes NightKey and phone apps show).</summary>
public static class Totp
{
    public static string Code(byte[] secret, DateTimeOffset when, int digits = 6, int period = 30)
    {
        long counter = when.ToUnixTimeSeconds() / period;
        Span<byte> msg = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(msg, counter);
        var hash = HMACSHA1.HashData(secret, msg);
        int offset = hash[^1] & 0x0F;
        int binary = (hash[offset] & 0x7F) << 24 | hash[offset + 1] << 16 | hash[offset + 2] << 8 | hash[offset + 3];
        return (binary % (int)Math.Pow(10, digits)).ToString().PadLeft(digits, '0');
    }

    /// <summary>Accepts the current code and the ones either side of it (clock drift). Returns the time step it matched, for one-time use.</summary>
    public static long? Check(byte[] secret, string code, DateTimeOffset now, int period = 30)
    {
        code = new string((code ?? "").Where(char.IsDigit).ToArray());
        if (code.Length != 6) return null;
        long step = now.ToUnixTimeSeconds() / period;
        for (int d = -1; d <= 1; d++)
        {
            var at = DateTimeOffset.FromUnixTimeSeconds((step + d) * period);
            if (SentinelCrypto.FixedTimeEquals(Code(secret, at), code)) return step + d;
        }
        return null;
    }

    public static byte[] NewSecret() => RandomNumberGenerator.GetBytes(20);

    public static string Base32(byte[] data)
    {
        const string a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var sb = new StringBuilder();
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = buffer << 8 | b;
            bits += 8;
            while (bits >= 5) { sb.Append(a[(buffer >> (bits - 5)) & 31]); bits -= 5; }
        }
        if (bits > 0) sb.Append(a[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static string SetupUri(string account, byte[] secret) =>
        $"otpauth://totp/{Uri.EscapeDataString("Night Tech Sentinel:" + account)}?secret={Base32(secret)}&issuer={Uri.EscapeDataString("Night Tech Sentinel")}";
}

/// <summary>Console passwords: PBKDF2-SHA256 with 600,000 rounds and a random salt.</summary>
public static class Passwords
{
    public const int Rounds = 600_000;

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Rounds, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2-sha256${Rounds}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Check(string password, string stored)
    {
        var parts = (stored ?? "").Split('$');
        if (parts.Length != 4 || parts[0] != "pbkdf2-sha256" || !int.TryParse(parts[1], out int rounds) || rounds < 100_000) return false;
        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(password ?? "", salt, rounds, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException) { return false; }
    }

    /// <summary>At least 12 characters, and not one of the passwords people use most.</summary>
    public static string? Problem(string password)
    {
        if (string.IsNullOrEmpty(password) || password.Length < 12) return "Use at least 12 characters.";
        var lower = password.ToLowerInvariant();
        string[] common = { "password", "123456", "qwerty", "letmein", "welcome", "nighttech", "sentinel", "admin" };
        if (common.Any(c => lower.Contains(c))) return "That password is too easy to guess.";
        if (password.Distinct().Count() < 5) return "Use more different characters.";
        return null;
    }
}
