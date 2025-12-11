namespace LamGC.AES_XTS.Tests;

public class XtsAesBufferedCipherTests
{
    private readonly byte[] _key1 = new byte[16];
    private readonly byte[] _key2 = new byte[16];

    private XtsAesCipherParameters CreateParams(
        XtsAesMode mode, 
        ulong sectorSize = 512, 
        ulong sectorIndex = 0)
    {
        return new XtsAesCipherParameters(mode, _key1, _key2, sectorSize, sectorIndex);
    }

    #region Basic Information
    
    [Fact]
    public void AlgorithmName_ShouldBeCorrect()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));
        Assert.Equal("AES/XTS", cipher.AlgorithmName);
    }
    
    [Fact]
    public void GetBlockSize_ShouldEqualAesBlockSize()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));
        Assert.Equal(16, cipher.GetBlockSize());
    }
    
    #endregion

    #region 生命周期与参数检查

    [Fact]
    public void Init_WithInvalidParameters_ShouldThrow()
    {
        Assert.Throws<ArgumentException>(() => 
            CreateParams(XtsAesMode.Continuous, 15));

        var invalidParameters = CreateParams(XtsAesMode.Continuous, 16);
        var sectorSizeProperty = typeof(XtsAesCipherParameters).GetProperty(nameof(invalidParameters.SectorSize));

        Assert.NotNull(sectorSizeProperty);

        var sectorSizeSetter = sectorSizeProperty.GetSetMethod(nonPublic: true)!;
        
        Assert.NotNull(sectorSizeSetter);
        
        sectorSizeSetter.Invoke(invalidParameters, new object[] { 15UL });
        
        Assert.Equal(15UL, invalidParameters.SectorSize);
        
        Assert.Throws<ArgumentException>(() => 
            new XtsAesBufferedCipher(true, invalidParameters));
    }

    [Fact]
    public void Lifecycle_Dispose_ShouldPreventUsage()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));
        
        cipher.Dispose();

        // 验证 Dispose 后所有公开方法都抛出 ObjectDisposedException 或 InvalidOperationException
        Assert.Throws<InvalidOperationException>(() => cipher.ProcessByte(0));
        Assert.Throws<InvalidOperationException>(() => cipher.ProcessBytes(new byte[16]));
        Assert.Throws<InvalidOperationException>(() => cipher.DoFinal());
        Assert.Throws<InvalidOperationException>(() => cipher.Reset());
    }

    [Fact]
    public void Reset_ShouldClearBufferAndCounters()
    {
        // 使用 Independent 模式测试, 因为该模式有内部计数器需要重置
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Independent, 32));

        // 1. 填入 10 字节数据 (进入 Buffer)
        cipher.ProcessBytes(new byte[10]); 
        
        // 2. Reset
        cipher.Reset();

        // 3. 再次填入 32 字节
        // 如果计数器没重置: 10 + 32 > 32 -> 抛异常
        // 这里会直接处理 16 字节, 为了确保后续 CTS 正确执行, 会缓存 16 字节.
        var handledOutput = cipher.ProcessBytes(new byte[32]);
        
        Assert.Equal(16, handledOutput.Length);
        
        var output = cipher.DoFinal();
        
        // 加上 Output 的 16 字节, 总计是 32 字节, 如果未重置, 那么 DoFinal 就会因为数据超出 Sector Size 而抛出异常.
        Assert.Equal(16, output.Length);
    }

    [Fact]
    public void DoFinal_ShouldAutoResetAfterExecute()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous, 32));
        
        Assert.Equal(0, cipher.GetOutputSize(0));
        
        cipher.DoFinal(Array.Empty<byte>(), 0);
        Assert.Equal(0, cipher.GetOutputSize(0));
        
        cipher.DoFinal(new byte[32], 0);
        Assert.Equal(0, cipher.GetOutputSize(0));

        cipher.ProcessBytes(new byte[32]);
        cipher.DoFinal(new byte[32], 0);
        Assert.Equal(0, cipher.GetOutputSize(0));
    }

    #endregion

    #region Independent 模式边界测试 (关键路径)

    [Fact]
    public void IndependentMode_ExactSectorSize_ShouldSucceed()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Independent, 32));

        // 分两次输入, 验证累加逻辑
        cipher.ProcessBytes(new byte[16]);
        var output = cipher.DoFinal(new byte[16]);

        Assert.Equal(32, output.Length);
    }

    [Fact]
    public void IndependentMode_ExceedingLimit_ShouldThrow_Immediately()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Independent, 32));

        // 1. 输入 32 字节 (占满)
        cipher.ProcessBytes(new byte[32]);

        // 2. 尝试再输入 1 字节 -> 应该立即抛出异常
        var ex = Assert.Throws<InvalidOperationException>(() => 
            cipher.ProcessByte(0));
        
        var ex2 = Assert.Throws<InvalidOperationException>(() => 
            cipher.ProcessBytes(new byte[] { 0 }));
        
        Assert.Contains("cannot exceed the specified sector size", ex.Message);
        Assert.Contains("cannot exceed the specified sector size", ex2.Message);
    }

    [Fact]
    public void IndependentMode_GetOutputSize_ShouldCheckLimit()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Independent, 32));

        cipher.ProcessBytes(new byte[20]); // 已处理 20

        // 询问: 再来 13 字节输出多大？ (20 + 13 = 33 > 32) -> 应该报错
        Assert.Throws<InvalidOperationException>(() => 
            cipher.GetOutputSize(13));
        
        // 询问: 再来 12 字节输出多大？ (20 + 12 = 32) -> OK
        Assert.Equal(32, cipher.GetOutputSize(12));
    }

    #endregion

    #region Continuous 模式与 CTS 逻辑

    [Theory]
    [InlineData(16)] // 1 Block
    [InlineData(32)] // 2 Blocks
    [InlineData(48)] // 3 Blocks
    public void StandardBlocks_RoundTrip_ShouldWork(int length)
    {
        VerifyRoundTrip(length, XtsAesMode.Continuous);
    }

    [Theory]
    [InlineData(31)] // 1 Block + 15 bytes CTS
    [InlineData(33)] // 2 Blocks + 1 byte CTS
    [InlineData(47)] // 2 Blocks + 15 bytes CTS
    public void CTS_RoundTrip_ShouldWork(int length)
    {
        VerifyRoundTrip(length, XtsAesMode.Continuous);
    }

    [Fact]
    public void DataUnit_LessThan16Bytes_ShouldThrow()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));

        var input = new byte[15]; 
        
        // XTS 根本不支持 < 16 字节
        Assert.Throws<ArgumentException>(() => cipher.DoFinal(input));
    }

    [Fact]
    public void CTS_AcrossSectorBoundary_ShouldThrow()
    {
        // [关键测试]: 验证 DoFinal 中新增的 CTS 跨扇区检查
        
        // 场景: SectorSize = 32 (2 blocks)。
        // 这里试图加密 33 字节。
        // 第 0 块 (0-15) -> Sector 0, Block 0 (处理完毕)
        // 剩余 17 字节在 Buffer 中。
        // Buffer 需要做 CTS: 前 16 字节是 Sector 0, Block 1。后 1 字节是 Sector 1, Block 0。
        // 这是跨扇区的 CTS, 必须被禁止。

        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous, 32));

        var input = new byte[33]; 
        
        // 应该抛出 DataLengthException, 提示 CTS 跨扇区
        var ex = Assert.Throws<ArgumentException>(() => cipher.DoFinal(input));
        Assert.Contains("Invalid data state for DoFinal at a sector boundary.", ex.Message);
    }
    
    [Fact]
    public void ContinuousMode_Rollover_ExactBoundary_ShouldWork()
    {
        // 验证正常的扇区切换 (非 CTS 跨越)
        // SectorSize = 32. 输入 64 字节 (正好 2 个扇区)

        var input = new byte[64];
        // 填充一些数据防止全0
        for(var i=0; i<64; i++) input[i] = (byte)i;

        var encryptCipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous, 32));
        var output = encryptCipher.DoFinal(input);
        Assert.Equal(64, output.Length);

        // 验证解密
        var decryptCipher = new XtsAesBufferedCipher(false, CreateParams(XtsAesMode.Continuous, 32));
        var decrypted = decryptCipher.DoFinal(output);
        Assert.Equal(input, decrypted);
    }

    #endregion

    #region Buffer 碎片整理测试

    [Fact]
    public void Buffer_Fragmentation_ByteByByte_ShouldMatchAllAtOnce()
    {
        var parms = CreateParams(XtsAesMode.Continuous);
        var cipher = new XtsAesBufferedCipher(true, parms);
        var input = new byte[100];
        Random.Shared.NextBytes(input);

        var expected = cipher.DoFinal(input);

        // 2. 逐字节处理
        cipher.Reset();
        using var ms = new MemoryStream();
        foreach (var b in input)
        {
            var outBuf = cipher.ProcessByte(b);
            ms.Write(outBuf);
        }
        var finalBuf = cipher.DoFinal();
        ms.Write(finalBuf);

        Assert.Equal(expected, ms.ToArray());
    }

    [Fact]
    public void Buffer_Fragmentation_RandomChunks_ShouldMatch()
    {
        var parms = CreateParams(XtsAesMode.Continuous);
        var cipher = new XtsAesBufferedCipher(true, parms);
        var input = new byte[500];
        Random.Shared.NextBytes(input);

        // 1. 一次性
        var expected = cipher.DoFinal(input);

        // 2. 随机大小 Chunk
        cipher.Reset();
        using var ms = new MemoryStream();
        var offset = 0;
        var rng = new Random(123);
        
        while (offset < input.Length)
        {
            var chunkSize = rng.Next(1, 50); // 1 到 49 字节
            chunkSize = Math.Min(chunkSize, input.Length - offset);
            
            var outBuf = cipher.ProcessBytes(input, offset, chunkSize);
            ms.Write(outBuf);
            
            offset += chunkSize;
        }
        var finalBuf = cipher.DoFinal();
        ms.Write(finalBuf);

        Assert.Equal(expected, ms.ToArray());
    }

    #endregion
    
    #region 长度输出预测测试

    [Fact]
    public void GetUpdateOutputSize_BufferBoundary_ShouldRespect31ByteLimit()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));

        // 场景 1: 输入 16 字节 (1个块)
        // 行为: 16 <= 31, 全部缓存, 不输出
        Assert.Equal(0, cipher.GetUpdateOutputSize(16));
        Assert.Equal(0UL, cipher.GetUpdateOutputSizeExact(16));

        // 场景 2: 输入 31 字节 (缓冲区满)
        // 行为: 31 <= 31, 全部缓存, 不输出
        Assert.Equal(0, cipher.GetUpdateOutputSize(31));
        Assert.Equal(0UL, cipher.GetUpdateOutputSizeExact(31));

        // 场景 3: 输入 32 字节 (超过缓冲区阈值)
        // 行为: 32 > 31, 触发处理。
        // 保留逻辑: TotalBlocks(2) - 1 = 1 个块被处理
        // 输出: 16 字节
        Assert.Equal(16, cipher.GetUpdateOutputSize(32));
        Assert.Equal(16UL, cipher.GetUpdateOutputSizeExact(32));
    }

    [Fact]
    public void GetOutputSize_IntOverflow_ShouldThrow()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));

        // 1. 填充 Buffer
        // 这里传入 31 字节可以直接填满 UnhandledBuffer, 因为如果不继续填充数据, 那么 Cipher 就会一直 Pending 这两个块.
        cipher.ProcessBytes(new byte[31]); 
    
        const int largeInput = int.MaxValue;
    
        // 3. 验证 GetOutputSize (DoFinal 逻辑, 包含所有数据) -> 肯定溢出
        Assert.Throws<InvalidOperationException>(() => cipher.GetOutputSize(largeInput));

        // 4. 验证 GetUpdateOutputSize (Update 逻辑, 保留数据) -> 依然溢出
        Assert.Throws<InvalidOperationException>(() => cipher.GetUpdateOutputSize(largeInput));
    }

    [Fact]
    public void GetOutputSizeExact_ShouldHandleLargeValues()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));
        
        cipher.ProcessBytes(new byte[16]); // Buffer = 16

        // 模拟一个超大的 ulong 输入
        const ulong largeInput = int.MaxValue + 100UL;
        
        // GetOutputSizeExact 应该能正常返回 ulong 结果而不抛异常
        // Total = largeInput + 16
        const ulong expected = largeInput + 16;
        
        Assert.Equal(expected, cipher.GetOutputSizeExact(largeInput));
    }

    [Fact]
    public void GetOutputSize_AfterReset_ShouldBeZeroBase()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));

        cipher.ProcessBytes(new byte[10]);
        // Reset 前, 预测值包含 Buffer
        Assert.Equal(20, cipher.GetOutputSize(10)); 

        cipher.Reset();
        // Reset 后, Buffer 清空, 预测值只包含输入
        Assert.Equal(10, cipher.GetOutputSize(10));
    }
    
    #endregion
    
    #region Advanced Buffer & Offset Handling Tests

    [Fact]
    public void ProcessBytes_WithOffsetAndLength_ShouldProcessCorrectly()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));

        // 构造一个包含 "干扰数据" 的数组
        var largeBuffer = new byte[100];
        Array.Fill(largeBuffer, (byte)0xFF); // 填充干扰数据
        
        // 在中间放置 32 字节的有效数据 (索引 10 到 41)
        var validData = new byte[32];
        for(var i=0; i<32; i++) validData[i] = (byte)i;
        Array.Copy(validData, 0, largeBuffer, 10, 32);

        // 调用带 Offset 的 ProcessBytes
        // 期望: 只处理 validData, 忽略前 10 和后 58 个 0xFF
        // ProcessBytes(input, inOff, length) -> 应该返回 16 字节 (1个块), 缓存 16 字节
        var output1 = cipher.ProcessBytes(largeBuffer, 10, 32);
        
        Assert.Equal(16, output1.Length);

        // DoFinal 获取剩余
        var output2 = cipher.DoFinal();
        Assert.Equal(16, output2.Length);

        // 验证解密回来的数据是否等于 validData
        var decryptCipher = new XtsAesBufferedCipher(false, CreateParams(XtsAesMode.Continuous));
        var fullOutput = output1.Concat(output2).ToArray();
        var decrypted = decryptCipher.DoFinal(fullOutput);
        
        Assert.Equal(validData, decrypted);
    }

    [Fact]
    public void ProcessBytes_ToOutputBuffer_ShouldWriteAtOffset()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));

        var input = new byte[32]; // 2 blocks
        var outputBuffer = new byte[100]; // 大 buffer
        var outOffset = 50;

        // ProcessBytes(input, output, outOff)
        // 输入 32 字节, 应该处理 16 字节 (1 block), 写入 outputBuffer[50..66]
        var len = cipher.ProcessBytes(input, outputBuffer, outOffset);

        Assert.Equal(16, len);
        
        // 验证是否真的写入了 index 50
        // (由于 key 是 0, input 是 0, output 不会是 0, 简单检查非零即可验证写入)
        Assert.NotEqual(0, outputBuffer[50]); 
        Assert.Equal(0, outputBuffer[49]); // 前一个字节不应被污染
    }

    [Fact]
    public void DoFinal_ToOutputBuffer_ShouldWriteAtOffset()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));

        // 先放入 32 字节
        cipher.ProcessBytes(new byte[32]); // 此时 Buffer 有 16 字节, 已输出 16 字节(假设用的是返回数组的方法)
        // 为了测试 DoFinal 的纯 Output 变体, 这里需要一种状态: Buffer 里有数据待输出
        // 上面 ProcessBytes 会处理前 16 字节。
        // 所以在这里重置一下, 只放 16 字节进 Buffer, 不让它输出
        cipher.Reset();
        cipher.ProcessBytes(new byte[16]); // Buffer = 16, Output = 0

        var outputBuffer = new byte[50];
        var outOffset = 10;

        // DoFinal(output, outOff) -> 应该把 Buffer 的 16 字节处理完写入
        var len = cipher.DoFinal(outputBuffer, outOffset);

        Assert.Equal(16, len);
        Assert.NotEqual(0, outputBuffer[10]);
        Assert.Equal(0, outputBuffer[9]);
    }

    [Fact]
    public void ProcessByte_ToOutputBuffer_ShouldAccumulateAndWrite()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));

        var outputBuffer = new byte[32];
        var bytesWritten = 0;

        // 逐字节输入 16 次
        for (var i = 0; i < 32; i++)
        {
            // ProcessByte(input, output, outOff)
            // 前 31 次应该返回 0, 第 32 次应该返回 16, 表示 unhandledBuffer 缓冲了新的块, 因此处理了先前的块.
            var written = cipher.ProcessByte((byte)i, outputBuffer, 0);
            Assert.Equal(i < 31 ? 0 : 16, written);

            bytesWritten += written;
        }
        
        // 当写入了 32 字节数据后, 应该处理了 16 字节.
        Assert.Equal(16, bytesWritten);
    }

    [Fact]
    public void DoFinal_WithInputAndOutputBuffer_ShouldHandleEverything()
    {
        // 测试 DoFinal(input, inOff, len, output, outOff) 这个最全参数的版本
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));

        var input = new byte[20]; // 16 + 4
        var output = new byte[20];
        
        // 一次性处理 20 字节 (需 CTS)
        var len = cipher.DoFinal(input, 0, 20, output, 0);
        
        Assert.Equal(20, len);
    }

    [Fact]
    public void IndependentMode_ProcessBytesWithOffset_ShouldCountCorrectly()
    {
        // 验证 Offset 版本的 ProcessBytes 是否也正确出发了 Independent 计数器检查
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Independent, 32));

        var buffer = new byte[100]; // 大 buffer

        // 1. 处理 20 字节 (合法)
        cipher.ProcessBytes(buffer, 0, 20);

        // 2. 尝试处理 13 字节 (20 + 13 = 33 > 32) -> 应该报错
        Assert.Throws<InvalidOperationException>(() => 
            cipher.ProcessBytes(buffer, 20, 13));
    }

    #endregion

    #region Output Size Consistency Tests (Prediction vs Reality)

    [Theory]
    [InlineData(16)] // 正好 1 块
    [InlineData(20)] // 1 块 + 4 字节 (需 CTS)
    [InlineData(32)] // 正好 2 块
    [InlineData(48)] // 正好 3 块
    public void GetOutputSize_ShouldMatchDoFinalOutputLength(int inputLength)
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));

        // 1. 预测
        var predictedSize = cipher.GetOutputSize(inputLength);
        var predictedSizeExact = cipher.GetOutputSizeExact((ulong)inputLength);

        // 2. 实际执行
        var input = new byte[inputLength];
        var output = cipher.DoFinal(input);

        // 3. 验证
        Assert.Equal(predictedSize, output.Length);
        // 额外验证 Exact 版本
        Assert.Equal(predictedSizeExact, (ulong)output.Length);
    }

    [Theory]
    [InlineData(32)] // 输入 32 -> 应该处理 16, 缓存 16
    [InlineData(48)] // 输入 48 -> 应该处理 32, 缓存 16
    public void GetUpdateOutputSize_ShouldMatchProcessBytesOutputLength(int inputLength)
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));

        // 1. 预测 Update 输出
        var predictedUpdateSize = cipher.GetUpdateOutputSize(inputLength);
        var predictedUpdateSizeExact = cipher.GetUpdateOutputSizeExact((ulong)inputLength);

        // 2. 实际执行 ProcessBytes
        var input = new byte[inputLength];
        var updateOutput = cipher.ProcessBytes(input);

        // 3. 验证
        Assert.Equal(predictedUpdateSize, updateOutput.Length);
        // 额外验证 Exact 版本
        Assert.Equal(predictedUpdateSizeExact, (ulong)updateOutput.Length);
    }

    [Fact]
    public void GetOutputSize_WithExistingBuffer_ShouldMatchActual()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));

        // 先填充 10 字节 Buffer
        cipher.ProcessBytes(new byte[10]);

        // 预测再输入 22 字节后的总输出 (10 + 22 = 32)
        var inputLen = 22;
        var predicted = cipher.GetOutputSize(inputLen);

        // 实际执行
        var output = cipher.DoFinal(new byte[inputLen]);

        Assert.Equal(predicted, output.Length);
    }

    [Fact]
    public void GetUpdateOutputSize_WithExistingBuffer_ShouldMatchActual()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous));

        // 先填充 10 字节
        cipher.ProcessBytes(new byte[10]);

        // 预测再输入 22 字节 (Total 32 -> 2 blocks)
        // Update 应该输出 1 个 block (16 bytes), 留 1 个在 buffer
        var inputLen = 22;
        var predicted = cipher.GetUpdateOutputSize(inputLen);

        // 实际执行
        var output = cipher.ProcessBytes(new byte[inputLen]);

        Assert.Equal(predicted, output.Length);
        Assert.Equal(16, output.Length);
    }

    [Fact]
    public void GetOutputSize_IndependentMode_ShouldMatchLimitCheck()
    {
        // 这个测试验证 Independent 模式下的预测是否也符合实际
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Independent, 32));

        // 预测输入 32 字节
        var predicted = cipher.GetOutputSize(32);
        
        // 实际执行
        var output = cipher.DoFinal(new byte[32]);

        Assert.Equal(predicted, output.Length);
        Assert.Equal(32, output.Length);
    }

    #endregion
    
    #region ProcessByte(s) 和 DoFinal 边界测试.

    [Fact]
    public void DoFinal_ProvidedShorterOutputBuf_ShouldThrows()
    {
        // 这个测试验证 Independent 模式下的预测是否也符合实际
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Independent, 32));

        // 同时输入和输出的情况.
        // 预测输入 32 字节
        var predicted = cipher.GetOutputSize(32);
        // 实际执行
        Assert.Throws<ArgumentException>(() => cipher.DoFinal(new byte[32], new byte[predicted - 1].AsSpan()));
        
        // 此时 Cipher 应该没有处理任何数据, DoFinal 预检查失败不会导致状态更新.
        Assert.Equal(0, cipher.GetOutputSize(0));

        // 此时填入一块数据.
        var processOutBuf = cipher.ProcessBytes(new byte[16]);
        Assert.Empty(processOutBuf);
        
        // 再次尝试无输入的情况.
        var predictedOnNotEmpty = cipher.GetOutputSize(0);
        // 实际执行
        Assert.Throws<ArgumentException>(() => cipher.DoFinal(new byte[predictedOnNotEmpty - 1].AsSpan()));
    }
    
    [Fact]
    public void ProcessBytes_ProvidedShorterOutputBuf_ShouldThrows()
    {
        // 这个测试验证 Independent 模式下的预测是否也符合实际
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Independent, 32));

        // 同时输入和输出的情况.
        // 预测输入 32 字节
        var predicted = cipher.GetUpdateOutputSize(32);
        // 实际执行
        Assert.Throws<ArgumentException>(() => cipher.ProcessBytes(new byte[32], new byte[predicted - 1].AsSpan()));
        
        // 此时 Cipher 应该没有处理任何数据, DoFinal 预检查失败不会导致状态更新.
        Assert.Equal(0, cipher.GetOutputSize(0));
    }

    [Fact]
    public void CheckInput_ProvidedWrongInputArgs_ShouldThrows()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Independent, 32));

        var input = new byte[32];

        Assert.Throws<ArgumentOutOfRangeException>(() => cipher.ProcessBytes(input, 32, 32));
        Assert.Throws<ArgumentOutOfRangeException>(() => cipher.ProcessBytes(input, 30, 3));
    }
    
    [Fact]
    public void ContinuousMode_DoFinal_ExecuteOnInputOutOfSectorSize_ShouldThrows()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Continuous, 32));

        // 此时填入数据使得 UnhandledBuffer 出现跨扇区.
        cipher.ProcessBytes(new byte[33]);
        
        // 再次尝试无输入的情况.
        var predictedOutLen = cipher.GetOutputSize(0);
        // 实际执行
        var ex = Assert.Throws<ArgumentException>(() => cipher.DoFinal(new byte[] { 0 }, new byte[predictedOutLen].AsSpan()));
        Assert.Contains("Invalid data state for DoFinal at a sector boundary.", ex.Message);
    }
    
    [Fact]
    public void IndependentMode_ProcessBytes_ExecuteOnInputOutOfSectorSize_ShouldThrows()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Independent, 32));

        // 实际执行
        var ex = Assert.Throws<InvalidOperationException>(() => cipher.ProcessBytes(new byte[33]));
        Assert.Contains("cannot exceed the specified sector size", ex.Message);
        
        Assert.Equal(0, cipher.GetOutputSize(0));

        cipher.ProcessBytes(new byte[32]);
        var ex2 = Assert.Throws<InvalidOperationException>(() => cipher.ProcessBytes(new byte[1]));
        Assert.Contains("cannot exceed the specified sector size", ex2.Message);
        
        Assert.Equal(16, cipher.GetOutputSize(0));
        
        var ex3 = Assert.Throws<InvalidOperationException>(() => cipher.ProcessBytes(new byte[1], new byte[32]));
        Assert.Contains("cannot exceed the specified sector size", ex3.Message);
    }
    
    [Fact]
    public void IndependentMode_ProcessByte_ExecuteOnInputOutOfSectorSize_ShouldThrows()
    {
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Independent, 32));

        cipher.ProcessBytes(new byte[32]);
        var ex = Assert.Throws<InvalidOperationException>(() => cipher.ProcessByte(0));
        Assert.Contains("cannot exceed the specified sector size", ex.Message);
        
        Assert.Equal(16, cipher.GetOutputSize(0));
        
        var ex2 = Assert.Throws<InvalidOperationException>(() => cipher.ProcessByte(0, new byte[32], 0));
        Assert.Contains("cannot exceed the specified sector size", ex2.Message);
    }
    
    [Fact]
    public void DoFinal_ExecuteOnEmptyUnhandledBuffer_ShouldReturnEmpty()
    {
        // 这个测试验证 Independent 模式下的预测是否也符合实际
        var cipher = new XtsAesBufferedCipher(true, CreateParams(XtsAesMode.Independent, 32));

        // 在没有输入任何数据的情况下直接 DoFinal, 由于 UnhandledBuffer 什么数据都没有, 因此 DoFinal 应直接返回空数组.

        Span<byte> outBuf = stackalloc byte[32];
        
        var outLen = cipher.DoFinal(outBuf);
        
        Assert.Equal(0, outLen);
        foreach (var b in outBuf) 
        {
            Assert.Equal(0, b);
        }
    }
    
    #endregion
    
    
    
    #region Helper Methods

    private void VerifyRoundTrip(int length, XtsAesMode mode)
    {
        // 使用大 SectorSize 避免测试 CTS 跨扇区问题, 专注测试加解密互逆
        var parms = CreateParams(mode, 4096); 

        var plainText = new byte[length];
        for (var i = 0; i < length; i++) plainText[i] = (byte)(i % 255);

        // Encrypt
        var encryptCipher = new XtsAesBufferedCipher(true, parms);
        var cipherText = encryptCipher.DoFinal(plainText);
        Assert.Equal(length, cipherText.Length);

        // Decrypt
        var decryptCipher = new XtsAesBufferedCipher(false, parms);
        var recovered = decryptCipher.DoFinal(cipherText);

        Assert.Equal(plainText, recovered);
    }

    #endregion
}