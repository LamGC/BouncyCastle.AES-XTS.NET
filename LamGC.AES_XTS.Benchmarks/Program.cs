using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;

namespace LamGC.AES_XTS.Benchmarks;

[MemoryDiagnoser]
[DisassemblyDiagnoser(printSource: true, exportHtml: true)]
[SimpleJob(RuntimeMoniker.Net10_0, baseline: true)]
[SimpleJob(RuntimeMoniker.Net80)]
[SimpleJob(RuntimeMoniker.Net60)]
public class AesXtsBenchmark
{
    
    public class AlgoConfig
    {
        private string Name { get; init; }
        public string Keys { get; init; }

        public AlgoConfig(string name, string keys)
        {
            Name = name;
            Keys = keys;
        }

        // BenchmarkDotNet 会调用这个方法来显示列名
        public override string ToString() => Name;
    }

    // 2. 提供参数源
    public static IEnumerable<AlgoConfig> AlgoConfigs()
    {
        // XTS-AES-128: Key1(16 bytes) + Key2(16 bytes) = 32 bytes
        yield return new AlgoConfig(
            "AES-128",
            "a581d051ae57a097552491dd3fc480af28d059b084f2273c6ac0ef7a74d484cb"
        );
        
        // XTS-AES-256: Key1(32 bytes) + Key2(32 bytes) = 64 bytes
        yield return new AlgoConfig(
            "AES-256", 
            "ef010ca1a3663e32534349bc0bae62232a1573348568fb9ef41768a7674f507a727f98755397d0e0aa32f830338cc7a926c773f09e57b357cd156afbca46e1a0"
        );
    }
    
    private XtsAesBufferedCipher _cipher = null!;
    private byte[] _inputData = null!;
    private byte[] _outputBuffer = null!;

    [Params(4096, 65536, 1048576, 17, 31, 4095)]
    public int DataSize;
    [ParamsSource(nameof(AlgoConfigs))]
    public AlgoConfig KeyConfig = null!;
    
    [GlobalSetup]
    public void Setup()
    {
        _inputData = new byte[DataSize];
        _outputBuffer = new byte[DataSize];
        Random.Shared.NextBytes(_inputData);

        var keys = KeyConfig.Keys;
        var keysHex = Convert.FromHexString(keys);
        var halfLength = keysHex.Length / 2;
        
        var parameters = new XtsAesCipherParameters(
            XtsAesMode.Continuous, 
            keysHex[..halfLength], 
            keysHex[halfLength..], 
            4096
        );

        _cipher = new XtsAesBufferedCipher(true, parameters);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _cipher.Dispose();
    }

    [Benchmark]
    public int StreamingProcess_1KB_WithAllocation()
    {
        var handledBytes = 0;
        for (var i = 0; i < _inputData.Length / 1024; i++)
        {
            var bytes = _cipher.ProcessBytes(_inputData[(i * 1024)..(i * 1024 + 1024)]);
            handledBytes += bytes.Length;
        }

        handledBytes += _cipher.DoFinal().Length;
        return handledBytes;
    }
    
    [Benchmark]
    public int StreamingProcess_1KB_ZeroAllocation()
    {
        var handledBytes = 0;
        Span<byte> outputBuf = stackalloc byte[1024];
        for (var i = 0; i < _inputData.Length / 1024; i++)
        {
            handledBytes += _cipher.ProcessBytes(_inputData.AsSpan(i * 1024, 1024), outputBuf);
        }

        handledBytes += _cipher.DoFinal(outputBuf);
        return handledBytes;
    }
    
    [Benchmark]
    public int StreamingProcess_2KB_WithAllocation()
    {
        var handledBytes = 0;
        for (var i = 0; i < _inputData.Length / 2048; i++)
        {
            var bytes = _cipher.ProcessBytes(_inputData[(i * 2048)..(i * 2048 + 2048)]);
            handledBytes += bytes.Length;
        }

        handledBytes += _cipher.DoFinal().Length;
        return handledBytes;
    }
    
    [Benchmark]
    public int StreamingProcess_2KB_ZeroAllocation()
    {
        var handledBytes = 0;
        Span<byte> outputBuf = stackalloc byte[2048];
        for (var i = 0; i < _inputData.Length / 2048; i++)
        {
            handledBytes += _cipher.ProcessBytes(_inputData.AsSpan(i * 2048, 2048), outputBuf);
        }

        handledBytes += _cipher.DoFinal(outputBuf);
        return handledBytes;
    }
    
    [Benchmark(Baseline = true)]
    public byte[] DoFinal_WithAllocation()
    {
        return _cipher.DoFinal(_inputData);
    }

    [Benchmark]
    public int DoFinal_ZeroAllocation()
    {
        return _cipher.DoFinal(_inputData, _outputBuffer, 0);
    }
}

internal static class Program
{
    private static void Main()
    {
        BenchmarkRunner.Run<AesXtsBenchmark>();
    }
}