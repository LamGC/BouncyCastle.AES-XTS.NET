namespace LamGC.AES_XTS.Tests;

public class XtsTweakMathTests
{
    // 用于测试的 Alpha 乘法是否符合预期 (Little Endian XTS 定义)
    [Fact]
    public void MultiplyByAlpha_StandardVectors_ShouldMatch()
    {
        // Case 1: 1 -> 2 (无进位)
        byte[] input1 = new byte[16]; input1[0] = 1;
        byte[] expected1 = new byte[16]; expected1[0] = 2;
        
        AbstractXtsTweakGenerator.MultiplyByAlpha(input1);
        Assert.Equal(expected1, input1);

        // Case 2: 0x80...00 -> GF Feedback (有进位)
        // 0x80 在 byte[15] (Little Endian 的最高字节) 对应 GF(2^128) 的 x^127
        // 左移后溢出，应该 XOR 0x87 (10000111) -> byte[0]
        byte[] input2 = new byte[16]; input2[15] = 0x80;
        byte[] expected2 = new byte[16]; expected2[0] = 0x87;
        
        AbstractXtsTweakGenerator.MultiplyByAlpha(input2);
        Assert.Equal(expected2, input2);
    }

    // 验证快速算法 (GfPow2 + GfMultiply) 与 慢速循环算法 (Loop) 结果是否完全一致
    [Theory]
    [InlineData(10)]
    [InlineData(100)]
    [InlineData(2048)] // 阈值边界
    [InlineData(2049)] // 阈值边界 + 1
    [InlineData(5000)] // 远超阈值
    public void FastMath_ShouldMatch_IterativeMath(ulong power)
    {
        // 模拟一个初始 Tweak (全1)
        byte[] initialTweak = new byte[16];
        Array.Fill(initialTweak, (byte)0x01);

        // 1. 慢速计算: 循环调用 MultiplyByAlpha
        byte[] slowResult = initialTweak.ToArray();
        for (ulong i = 0; i < power; i++)
        {
            AbstractXtsTweakGenerator.MultiplyByAlpha(slowResult);
        }

        // 2. 快速计算: MultiplyByAlphaFast
        byte[] fastResult = initialTweak.ToArray();
        AbstractXtsTweakGenerator.MultiplyByAlphaFast(fastResult, power);

        Assert.Equal(slowResult, fastResult);
    }
}

public class XtsTweakGeneratorTests
{
    private readonly byte[] _dummyKey = new byte[32]; // 256-bit key

    [Fact]
    public void CalculateTweak_BelowAndAboveThreshold_ShouldBeConsistent()
    {
        var generator = new XtsTweakGenerator(_dummyKey);
        ulong sector = 123;
        
        // 1. 边界测试：2048 (走循环路径)
        var tweakAtThreshold = generator.CalculateTweak(sector, AbstractXtsTweakGenerator.FastTweakMathThreshold);
        
        // 2. 边界测试：2049 (走快速路径)
        var tweakAbove = generator.CalculateTweak(sector, AbstractXtsTweakGenerator.FastTweakMathThreshold + 1);

        // 验证：手动将 2048 的结果再乘一次 alpha，应该等于 2049 的结果
        AbstractXtsTweakGenerator.MultiplyByAlpha(tweakAtThreshold);
        Assert.Equal(tweakAtThreshold, tweakAbove);
    }
    
    [Fact]
    public void CalculateTweak_WithSectorIndexBytes_ShouldMatchUlong()
    {
        var generator = new XtsTweakGenerator(_dummyKey);
        ulong sector = 0x1122334455667788;
        
        var resultUlong = generator.CalculateTweak(sector, 0);
        
        var sectorBytes = new byte[16];
        BitConverter.TryWriteBytes(sectorBytes, sector);
        var resultBytes = generator.CalculateTweak(sectorBytes, 0);
        
        Assert.Equal(resultUlong, resultBytes);
    }
}

public class XtsTweakStatefulGeneratorTests
{
    private readonly byte[] _dummyKey = new byte[32];

    [Fact]
    public void Sequence_ShouldMatchStatelessGenerator()
    {
        const ulong sectorSize = 4096; // 256 blocks
        var stateful = new XtsTweakStatefulGenerator(_dummyKey, sectorSize, startSectorIndex: 10);
        var stateless = new XtsTweakGenerator(_dummyKey);

        for (ulong i = 0; i < 50; i++)
        {
            // 注意：CurrentTweak 是 ReadOnlySpan，需要转数组进行比较
            var tweakStateful = stateful.CurrentTweak.ToArray();
            var tweakStateless = stateless.CalculateTweak(10, i); // Sector 10, Block i

            Assert.Equal(tweakStateless, tweakStateful);
            stateful.MoveNext();
        }
    }

    [Fact]
    public void Rollover_StandardSector_ShouldIncrementSectorAndResetBlock()
    {
        // 设定 SectorSize 为 32 字节 (正好 2 个块: Block 0, Block 1)
        const ulong sectorSize = 32;
        const ulong startSector = 5;
        
        var stateful = new XtsTweakStatefulGenerator(_dummyKey, sectorSize, startSectorIndex: startSector);
        var stateless = new XtsTweakGenerator(_dummyKey);

        // Call 1: Sector 5, Block 0
        Assert.Equal(stateless.CalculateTweak(5, 0), stateful.GetTweakAndMove());
        Assert.Equal(5UL, stateful.CurrentSectorIndex);
        Assert.Equal(1UL, stateful.CurrentBlockIndex); // 此时指向 Block 1

        // Call 2: Sector 5, Block 1 (这是 Sector 5 的最后一个 Block)
        Assert.Equal(stateless.CalculateTweak(5, 1), stateful.GetTweakAndMove());
        
        // 关键修正：在 GetTweakAndMove 内部，MoveNext() 被调用。
        // 因为 Block 1 是最后一个块，MoveNext 会将 Index 推到 2 -> 触发 Rollover -> 重置为 0，Sector++
        Assert.Equal(6UL, stateful.CurrentSectorIndex); // Sector 应该变成 6
        Assert.Equal(0UL, stateful.CurrentBlockIndex);  // Block 应该变成 0

        // Call 3: Sector 6, Block 0 (新扇区的第一个块)
        Assert.Equal(stateless.CalculateTweak(6, 0), stateful.GetTweakAndMove());
        Assert.Equal(6UL, stateful.CurrentSectorIndex);
        Assert.Equal(1UL, stateful.CurrentBlockIndex);
    }

    [Fact]
    public void Rollover_PartialBlockSector_ShouldHandleRoundUp()
    {
        // 设定 SectorSize 为 33 字节 (2个完整块 + 1字节) -> TotalBlockCount 应该是 3 (0, 1, 2)
        const ulong sectorSize = 33; 
        var stateful = new XtsTweakStatefulGenerator(_dummyKey, sectorSize, startSectorIndex: 0);

        // Block 0
        stateful.MoveNext(); 
        Assert.Equal(1UL, stateful.CurrentBlockIndex);

        // Block 1
        stateful.MoveNext(); 
        Assert.Equal(2UL, stateful.CurrentBlockIndex);
        
        // Block 2 (Partial Block 的 Tweak)
        stateful.MoveNext(); 
        
        // 关键修正：Block 2 是最后一个块 (Index = 2)。
        // MoveNext() 导致 Index -> 3 -> 触发 Rollover -> 重置为 0, Sector++
        Assert.Equal(1UL, stateful.CurrentSectorIndex); // Sector 0 -> 1
        Assert.Equal(0UL, stateful.CurrentBlockIndex);  // Block 2 -> 0

        // Block 3 -> 实际上是下一个 Sector 的 Block 0 (Sector 1, Block 0)
        // 此时生成器已经就绪，再次 MoveNext 会推进到 Sector 1, Block 1
        stateful.MoveNext(); 
        
        Assert.Equal(1UL, stateful.CurrentSectorIndex);
        Assert.Equal(1UL, stateful.CurrentBlockIndex);
    }

    [Fact]
    public void Reset_WithStartBlockIndex_ShouldResumeCorrectly()
    {
        ulong sectorSize = 1024;
        ulong startBlock = 50;
        ulong startSector = 2;
        
        var stateful = new XtsTweakStatefulGenerator(_dummyKey, sectorSize, startSector, startBlock);
        var stateless = new XtsTweakGenerator(_dummyKey);

        // 第一次 GetNextTweak 应该返回 Sector 2, Block 50 的 Tweak
        var tweak = stateful.GetTweakAndMove();
        var expected = stateless.CalculateTweak(startSector, startBlock);
        
        Assert.Equal(expected, tweak);
        
        // 状态检查
        Assert.Equal(startSector, stateful.CurrentSectorIndex);
        Assert.Equal(startBlock + 1, stateful.CurrentBlockIndex);
    }

    [Fact]
    public void Reset_WithLargeStartBlock_ShouldUseFastMath()
    {
        // 测试当 StartBlockIndex > 2048 时，构造函数是否正确使用了 FastMath 路径
        const ulong startBlock = 3000; 
        var stateful = new XtsTweakStatefulGenerator(_dummyKey, 4096 * 16, 0, startBlock);
        var stateless = new XtsTweakGenerator(_dummyKey);

        var tweak = stateful.GetTweakAndMove();
        Assert.Equal(stateless.CalculateTweak(0, startBlock), tweak);
    }

    [Fact]
    public void Constructor_InvalidArguments_ShouldThrow()
    {
        // SectorSize < 16
        Assert.Throws<ArgumentException>((Func<XtsTweakStatefulGenerator>)(() => 
            new XtsTweakStatefulGenerator(_dummyKey, 15)));

        // StartBlockIndex 超出 SectorSize 范围
        Assert.Throws<ArgumentOutOfRangeException>((Func<XtsTweakStatefulGenerator>)(() => 
            new XtsTweakStatefulGenerator(_dummyKey, 32, 0, 2)));
    }

    [Fact]
    public void Dispose_CleanTweakSpan_ShouldBeCleaned()
    {
        var stateful = new XtsTweakStatefulGenerator(_dummyKey, 64, startSectorIndex: 0);
        
        var currentTweakSpan = stateful.CurrentTweak;
        
        stateful.Dispose();

        foreach (var b in currentTweakSpan)
        {
            Assert.Equal(0, b);
        }
    }
}
