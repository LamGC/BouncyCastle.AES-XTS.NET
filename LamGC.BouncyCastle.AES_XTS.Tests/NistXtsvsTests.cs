using System.Collections;

namespace LamGC.BouncyCastle.AES_XTS.Tests;

/// <summary>
/// NIST XTSVS (XTS-AES Validation System) 测试.
/// 使用 NIST CAVP 提供的官方测试向量文件进行验证.
/// </summary>
public class NistXTSVSTests
{
    
    [Theory]
    [ClassData(typeof(NistXts128TestVectorLoader))]
    public void VerifyNistXtsValidateTests_Aes128_ShouldPassed(NistXtsTestVector vector)
    {
        if (vector.DataUnitLength % 8 != 0)
        {
            return;
        }
        
        XtsAesCipherParameters parameters = new(XtsAesMode.Continuous, vector.Key1, vector.Key2, vector.DataUnitLength / 8, vector.SectorIndex);

        var cipher = new XtsAesBufferedCipher();
        cipher.Init(vector.IsEncrypt, parameters);

        if (vector.IsEncrypt)
        {
            Assert.Equal(vector.CipherText, cipher.DoFinal(vector.PlainText));
        }
        else
        {
            Assert.Equal(vector.PlainText, cipher.DoFinal(vector.CipherText));
        }
    }
    
    [Theory]
    [ClassData(typeof(NistXts256TestVectorLoader))]
    public void VerifyNistXtsValidateTests_Aes256_ShouldPassed(NistXtsTestVector vector)
    {
        if (vector.DataUnitLength % 8 != 0)
        {
            return;
        }
        
        XtsAesCipherParameters parameters = new(XtsAesMode.Continuous, vector.Key1, vector.Key2, vector.DataUnitLength, vector.SectorIndex);

        var cipher = new XtsAesBufferedCipher();
        cipher.Init(vector.IsEncrypt, parameters);

        if (vector.IsEncrypt)
        {
            Assert.Equal(vector.CipherText, cipher.DoFinal(vector.PlainText));
        }
        else
        {
            Assert.Equal(vector.PlainText, cipher.DoFinal(vector.CipherText));
        }
    }
    
}

public class NistXtsTestVector
{
    public required int Count { get; init; }
    public required bool IsEncrypt { get; init; }
    public required uint DataUnitLength { get; init; }
    public required byte[] Key1 { get; init; }
    public required byte[] Key2 { get; init; }
    public required ulong SectorIndex { get; init; }
    public required byte[] PlainText { get; init; }
    public required byte[] CipherText { get; init; }
    
    public override string ToString() => 
        $"Count: {Count}, Mode: {(IsEncrypt ? "Encrypt" : "Decrypt")}";
}

public class NistXtsTestVectorLoaderBase(string testVectorFilePath, int expectedKeySizeBits) : IEnumerable<object[]>
{
    // 例如 128 或 256

    // 修改构造函数，增加 expectedKeySizeBits

    public IEnumerator<object[]> GetEnumerator()
    {
        if (!File.Exists(testVectorFilePath))
        {
            throw new FileNotFoundException("Test vector file not found", testVectorFilePath);
        }

        using var reader = new StreamReader(testVectorFilePath);

        bool? currentIsEncrypt = null;
        
        int? count = null;
        uint? dataUnitLen = null;
        byte[]? key1 = null;
        byte[]? key2 = null;
        ulong? sectorIndex = null;
        byte[]? pt = null;
        byte[]? ct = null;

        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            var cleanLine = HandleLine(line);
            if (string.IsNullOrEmpty(cleanLine)) continue;

            if (cleanLine.StartsWith('['))
            {
                var sectionName = cleanLine.Trim('[', ']').ToUpperInvariant();
                currentIsEncrypt = sectionName switch
                {
                    "ENCRYPT" => true,
                    "DECRYPT" => false,
                    _ => currentIsEncrypt
                };
                continue;
            }

            var (k, v) = ParseConfigKeyPair(cleanLine);
            if (string.Equals(k, "COUNT", StringComparison.OrdinalIgnoreCase))
            {
                if (count.HasValue && IsVectorReady(key1, sectorIndex, pt, ct))
                {
                    yield return
                    [
                        CreateVector(currentIsEncrypt, count, dataUnitLen, key1, key2, sectorIndex, pt, ct)
                    ];
                }

                
                count = int.Parse(v);
                sectorIndex = null;
                pt = null;
                ct = null;
                key1 = null; 
                key2 = null;
                dataUnitLen = null;
            }
            else if (string.Equals(k, "DataUnitLen", StringComparison.OrdinalIgnoreCase))
            {
                dataUnitLen = uint.Parse(v);
            }
            else if (string.Equals(k, "Key", StringComparison.OrdinalIgnoreCase))
            {
                var fullKey = Convert.FromHexString(v);
                var expectedTotalBytes = expectedKeySizeBits / 8 * 2;
                if (fullKey.Length != expectedTotalBytes)
                {
                    throw new InvalidDataException(
                        $"Key length mismatch in file {testVectorFilePath}. " +
                        $"Expected AES-{expectedKeySizeBits} (total {expectedTotalBytes} bytes), " +
                        $"but got {fullKey.Length} bytes.");
                }
                
                var halfLen = fullKey.Length / 2;
                key1 = fullKey[..halfLen];
                key2 = fullKey[halfLen..];
            }
            else if (string.Equals(k, "DataUnitSeqNumber", StringComparison.OrdinalIgnoreCase))
            {
                sectorIndex = ulong.Parse(v);
            }
            else if (string.Equals(k, "PT", StringComparison.OrdinalIgnoreCase))
            {
                pt = Convert.FromHexString(v);
            }
            else if (string.Equals(k, "CT", StringComparison.OrdinalIgnoreCase))
            {
                ct = Convert.FromHexString(v);
            }
        }

        if (count.HasValue && IsVectorReady(key1, sectorIndex, pt, ct))
        {
            yield return
            [
                CreateVector(currentIsEncrypt, count, dataUnitLen, key1, key2, sectorIndex, pt, ct)
            ];
        }
    }

    private static bool IsVectorReady(byte[]? k1, ulong? seq, byte[]? p, byte[]? c)
    {
        return k1 != null && seq.HasValue && p != null && c != null;
    }

    private static NistXtsTestVector CreateVector(
        bool? isEncrypt, int? count, uint? len, byte[]? k1, byte[]? k2, ulong? seq, byte[]? pt, byte[]? ct)
    {
        if (isEncrypt == null) throw new InvalidDataException("Missing [ENCRYPT]/[DECRYPT] section header.");
        
        return new NistXtsTestVector
        {
            Count = count!.Value,
            IsEncrypt = isEncrypt.Value,
            DataUnitLength = len ?? (uint)(pt!.Length * 8),
            Key1 = k1!,
            Key2 = k2!,
            SectorIndex = seq!.Value,
            PlainText = pt!,
            CipherText = ct!
        };
    }
    
    private static string? HandleLine(string? line)
    {
        if (line == null) return null;
        var indexOf = line.IndexOf('#');
        return (indexOf == -1 ? line : line[..indexOf]).Trim();
    }

    private static (string, string) ParseConfigKeyPair(string line)
    {
        var indexOfSep = line.IndexOf('=');
        return indexOfSep == -1 ? ("", "") : 
            (line[..indexOfSep].Trim(), line[(indexOfSep + 1)..].Trim());
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

public class NistXts128TestVectorLoader() : NistXtsTestVectorLoaderBase(Path.Combine("XTSTestVectors",
    "format tweak value input - data unit seq no", "XTSGenAES128.rsp"), 128);
public class NistXts256TestVectorLoader() : NistXtsTestVectorLoaderBase(Path.Combine("XTSTestVectors",
    "format tweak value input - data unit seq no", "XTSGenAES256.rsp"), 256);