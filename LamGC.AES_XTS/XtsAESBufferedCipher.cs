using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace LamGC.AES_XTS
{
    public class XtsAesBufferedCipher : IDisposable
    {

        public const int AesBlockSize = 16;

        private readonly bool _forEncryption;
        private XtsAesMode _mode;
        private readonly Aes _dataEncEngine = Aes.Create();
        
        private XtsAesCipherParameters? _parameters;
        private XtsTweakStatefulGenerator _tweakGenerator = null!;

        private bool _disposed;

        private ulong SectorSize => _tweakGenerator.SectorSize;

        private ulong CurrentSectorIndex => _tweakGenerator.CurrentSectorIndex;
        private ulong CurrentBlockIndexInSector => _tweakGenerator.CurrentBlockIndex;
        private ulong TotalBlockCountInSector => (SectorSize + AesBlockSize - 1) / AesBlockSize;

        private readonly byte[] _unhandledBuffer = new byte[31 /* AesBlockSize * 2 - 1 */];
        /// <summary>
        /// 当前已存储的未处理字节数.
        /// </summary>
        private int _unhandledBufferLength;

#if NET7_0_OR_GREATER
        private UInt128 _totalBytesProcessedInCurrentSector = 0;
#else
        private ulong _totalBytesProcessedInCurrentSector;
#endif
    
        public XtsAesBufferedCipher(bool forEncryption, XtsAesCipherParameters parameters)
        {
            CheckParameters(parameters);
        
            _parameters = parameters;
            _forEncryption = forEncryption;
            Reset(true);
        }

        private static void CheckParameters(XtsAesCipherParameters parameters)
        {
            if (parameters.SectorSize < 16)
            {
                throw new ArgumentException("The sector size must be greater than or equal to 16 bytes.");
            }
        }
    
        public void Reset()
        {
            CheckState();
            Reset(false);
        }

        private void Reset(bool resetParameters)
        {
            if (_parameters == null)
            {
                throw new ArgumentException("XtsAESCipherParameters must be initialized!");
            }

            if (resetParameters)
            {
                _mode = _parameters.Mode;

                _dataEncEngine.Key = _parameters.Key1;
                _dataEncEngine.Mode = CipherMode.ECB;
                _dataEncEngine.Padding = PaddingMode.None;

                _tweakGenerator = new XtsTweakStatefulGenerator(_parameters.Key2, _parameters.SectorSize, _parameters.SectorIndex);
            }

            _tweakGenerator.Reset(_parameters.SectorSize, _parameters.SectorIndex);
            XtsUtils.SecureWipe(_unhandledBuffer);
            _unhandledBufferLength = 0;
            _totalBytesProcessedInCurrentSector = 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void CheckState()
        {
            if (_disposed)
            {
                throw new InvalidOperationException("Cipher is disposed.");
            }
        }

        public int GetBlockSize()
        {
            return AesBlockSize;
        }

        public int GetOutputSize(int inputLen)
        {
            XtsParameterValidators.ThrowIfNegative(inputLen);
            CheckState();
        
            if (_mode == XtsAesMode.Independent)
            {
                var totalDataForSector = 
                    _totalBytesProcessedInCurrentSector + (ulong)inputLen;

                if (totalDataForSector > SectorSize)
                {
                    throw new InvalidOperationException(
                        $"In Independent mode, the total data for sector {CurrentSectorIndex} " +
                        $"({totalDataForSector} bytes) cannot exceed the specified sector size ({SectorSize} bytes).");
                }
            }
        
            var outputSize = (long) _unhandledBufferLength + inputLen;
            if (outputSize > int.MaxValue)
            {
                throw new InvalidOperationException("Input data is too large for the IBufferedCipher API.");
            }

            return (int)outputSize;
        }
    
        public ulong GetOutputSizeExact(ulong inputLen)
        {
            CheckState();
        
            if (_mode == XtsAesMode.Independent)
            {
                var totalDataForSector = 
                    _totalBytesProcessedInCurrentSector + inputLen;

                if (totalDataForSector > SectorSize)
                {
                    throw new InvalidOperationException(
                        $"In Independent mode, the total data for sector {CurrentSectorIndex} " +
                        $"({totalDataForSector} bytes) cannot exceed the specified sector size ({SectorSize} bytes).");
                }
            }
        
            return inputLen + (ulong) _unhandledBufferLength;
        }

        public int GetUpdateOutputSize(int inputLen)
        {
            XtsParameterValidators.ThrowIfNegative(inputLen);
            CheckState();
        
            if (_mode == XtsAesMode.Independent)
            {
                var totalDataForSector = 
                    _totalBytesProcessedInCurrentSector + (ulong)inputLen;

                if (totalDataForSector > SectorSize)
                {
                    throw new InvalidOperationException(
                        $"In Independent mode, the total data for sector {CurrentSectorIndex} " +
                        $"({totalDataForSector} bytes) cannot exceed the specified sector size ({SectorSize} bytes).");
                }
            }

            var totalData = (long)_unhandledBufferLength + inputLen;
            var totalBlocks = totalData / 16;
            var blocksToProcess = totalBlocks > 0 ? totalBlocks - 1 : 0;
        
            var outputSize = blocksToProcess * 16;

            if (outputSize > int.MaxValue)
            {
                throw new InvalidOperationException("SectorSize is too large for the IBufferedCipher API.");
            }
        
            return (int)outputSize; 
        }

        public ulong GetUpdateOutputSizeExact(ulong inputLen)
        {
            CheckState();
        
            if (_mode == XtsAesMode.Independent)
            {
                var totalDataForSector = 
                    _totalBytesProcessedInCurrentSector + inputLen;

                if (totalDataForSector > SectorSize)
                {
                    throw new InvalidOperationException(
                        $"In Independent mode, the total data for sector {CurrentSectorIndex} " +
                        $"({totalDataForSector} bytes) cannot exceed the specified sector size ({SectorSize} bytes).");
                }
            }
        
            var totalData = (ulong)_unhandledBufferLength + inputLen;
            var totalBlocks = totalData / 16;
            var blocksToProcess = totalBlocks > 0 ? totalBlocks - 1 : 0;

            return blocksToProcess * 16;
        }
    
        /// <summary>
        /// 根据 forEncryption 来执行 AES 操作.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ProcessAesBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
#if NET6_0_OR_GREATER
        if (_forEncryption)
        {
            _dataEncEngine.EncryptEcb(input, output, PaddingMode.None);
        }
        else
        {
            _dataEncEngine.DecryptEcb(input, output, PaddingMode.None);
        }
#else
            _cipher.TransformBlockSpan(input, output);
#endif
        }
    
        /// <summary>
        /// 对传入的数据执行加解密操作.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <returns></returns>
        private int ProcessBytes0(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (_mode == XtsAesMode.Independent)
            {
                var totalDataForSector = 
                    _totalBytesProcessedInCurrentSector + (ulong)input.Length;

                if (totalDataForSector > SectorSize)
                {
                    // 注意, 该异常消息被 IndependentMode_ExceedingLimit_ShouldThrow_Immediately 测试项引用.
                    throw new InvalidOperationException(
                        $"In Independent mode, the total data for sector {CurrentSectorIndex} " +
                        $"({totalDataForSector} bytes) cannot exceed the specified sector size ({SectorSize} bytes). " +
                        $"({_totalBytesProcessedInCurrentSector} bytes already processed, {_unhandledBufferLength} bytes buffered).");
                }
            
                _totalBytesProcessedInCurrentSector += (ulong)input.Length;
            }
        
            if (input.Length + _unhandledBufferLength <= _unhandledBuffer.Length)
            {
                input.CopyTo(_unhandledBuffer.AsSpan()[_unhandledBufferLength..]);
                _unhandledBufferLength += input.Length;
                return 0;
            }

            var actualInputLength = _unhandledBufferLength + input.Length;
            var actualInput = actualInputLength < 1024 ? stackalloc byte[actualInputLength] : new byte[actualInputLength];
        
            try
            {
                if (_unhandledBufferLength > 0)
                {
                    _unhandledBuffer.AsSpan(0, _unhandledBufferLength)
                        .CopyTo(actualInput);
                }
        
                input.CopyTo(actualInput[_unhandledBufferLength..]);

                var blockCount = Math.Max(0, actualInput.Length / 16 - 1);
                var requiredSpace = blockCount * 16;
                if (output.Length < requiredSpace)
                {
                    throw new ArgumentException(
                        $"The provided output array has an insufficient length (required: {blockCount * 16}, actual: {output.Length})",
                        nameof(output));
                }

                Span<byte> inputBlock = stackalloc byte[16];
                Span<byte> outputBlock = stackalloc byte[16];
                try
                {
                    for (var i = 0; i < blockCount; i++)
                    {
                        actualInput.Slice(i * 16, 16).CopyTo(inputBlock);

                        ProcessXtsBlock(inputBlock, outputBlock);

                        outputBlock.CopyTo(output.Slice(i * 16, 16));
                    }
                }
                finally
                {
                    XtsUtils.SecureWipe(inputBlock);
                    XtsUtils.SecureWipe(outputBlock);
                }

                var startToBufIndex = blockCount * 16;
                XtsUtils.SecureWipe(_unhandledBuffer);
                actualInput[startToBufIndex..].CopyTo(_unhandledBuffer);
                _unhandledBufferLength = actualInput.Length - startToBufIndex;

                return blockCount * 16;
            }
            finally
            {
                XtsUtils.SecureWipe(actualInput);
            }
        }

        /// <summary>
        /// 对一个 16 字节的块执行加解密操作.
        /// </summary>
        /// <param name="input">传入的块数据, 该 Span 会被修改.</param>
        /// <param name="output">处理后的块数据, 该 Span 会被修改.</param>
        private void ProcessXtsBlock(Span<byte> input, Span<byte> output)
        {
            var tweak = _tweakGenerator.CurrentTweak;
        
            try {
                XtsUtils.XorBlock(input, tweak);
                
                // 加密模式已经在初始化时为 dataEncEngine 设置.
                ProcessAesBlock(input, output);

                XtsUtils.XorBlock(output, tweak);
            } finally {
                _tweakGenerator.MoveNext();
            }
        }
    
        public byte[] ProcessByte(byte input)
        {
            CheckState();

            var output = new byte[GetUpdateOutputSize(1)];
            ProcessBytes0(MemoryMarshal.CreateReadOnlySpan(ref input, 1), output);
            return output;
        }

        public int ProcessByte(byte input, byte[] output, int outOff)
        {
            CheckState();
            return ProcessBytes0(MemoryMarshal.CreateReadOnlySpan(ref input, 1), output.AsSpan(outOff));
        }

        public int ProcessByte(byte input, Span<byte> output)
        {
            CheckState();
        
            var handledBytes = ProcessBytes0(MemoryMarshal.CreateReadOnlySpan(ref input, 1), output);
        
            return handledBytes;
        }

        /// <summary>
        /// 执行 ProcessBytes 时, 所允许的最大输入长度.
        /// </summary>
        /// <remarks>
        /// 这个值等于 2_147_483_632, 传入小于等于该长度的 input 时, 不会导致 outputBuf 长度移除导致创建失败.
        /// </remarks>
        public const int MaxInputSizeAtProcess = int.MaxValue - int.MaxValue % 16;
        /// <summary>
        /// 执行 DoFinal 并传入剩余数据时, 所允许的最大输入长度.
        /// </summary>
        /// <remarks>
        /// 这个值等于 2_147_483_616, 传入小于等于该长度的 input 时, 不会导致 outputBuf 长度移除导致创建失败.
        /// 相比于 MaxInputSizeAtProcess, 该值将范围进一步缩小多一个 AES 块, 这确保了当 DoFinal 操作执行时,
        /// 如果 unhandledBuffer 仍存在数据, 那么也能创建一个足够大小的 outputBuf 来容纳追加剩余数据后的最终处理数据.
        /// </remarks>
        public const int MaxInputSizeAtDoFinal = int.MaxValue - (int.MaxValue % 16 + 16);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void CheckInput(ReadOnlySpan<byte> input, bool isDoFinal = false)
        {
            CheckInput(input, 0, input.Length, isDoFinal);
        }
    
        /// <summary>
        /// CheckInput 仅负责检查 输入参数是否正确, 传入数据长度是否可以安全处理, 是否会出现跨扇区问题.
        /// </summary>
        /// <param name="input">输入数据.</param>
        /// <param name="offset">读取输入的偏移量.</param>
        /// <param name="length">要求读取的长度.</param>
        /// <param name="isDoFinal">此次检查是否来自 DoFinal 函数.</param>
        /// <exception cref="ArgumentOutOfRangeException">如果指定的 offset 和 length 不匹配, 则抛出该异常.</exception>
        /// <exception cref="ArgumentException">当传入的数据量超过安全范围, 或在调用 DoFinal 传入最后数据时出现跨扇区问题, 就会抛出该异常.</exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void CheckInput(ReadOnlySpan<byte> input, int offset, int length, bool isDoFinal = false)
        {
            XtsParameterValidators.ThrowIfNegative(offset);
            XtsParameterValidators.ThrowIfNegative(length);

            if (input.Length - offset < length)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "The provided offset and length fall outside the bounds of the input span.");
            }

            if (length > (isDoFinal ? MaxInputSizeAtDoFinal : MaxInputSizeAtProcess))
            {
                throw new ArgumentException($"The provided length ({length}) exceeds the safe range ({MaxInputSizeAtProcess}) for single processing.");
            }
        
            if (isDoFinal && _mode == XtsAesMode.Continuous)
            {
                var pendingDataLength = (long)_unhandledBufferLength + length;

                int finalChunkLength;
                if (pendingDataLength <= 16)
                {
                    finalChunkLength = (int)pendingDataLength;
                }
                else
                {
                    finalChunkLength = (int)(pendingDataLength % 16);
                    if (finalChunkLength == 0)
                    {
                        finalChunkLength = 16; // 最后一个块是完整的
                    }
                    else
                    {
                        finalChunkLength += 16; // 标准 CTS (e.g., 17-31 字节)
                    }
                }
            
                var nMinus1LoopBlocks = Math.Max(0, (pendingDataLength / 16) - 1);
                var pnMinus1BlockIndex = (CurrentBlockIndexInSector + (ulong)nMinus1LoopBlocks) % TotalBlockCountInSector;
            
                if (finalChunkLength > 16 && pnMinus1BlockIndex == TotalBlockCountInSector - 1)
                {
                    // 这就是你发现的那个“不可恢复的”跨扇区状态
                    throw new ArgumentException(
                        $"Invalid data state for DoFinal at a sector boundary. " +
                        $"This operation's total data length ({pendingDataLength} bytes) would result in an invalid " +
                        "CTS state, violating the XTS specification.");
                }
            }
        }
    
        public byte[] ProcessBytes(byte[] input)
        {
            CheckState();
            CheckInput(input);
        
            var outputBuf = new byte[GetUpdateOutputSize(input.Length)];
            ProcessBytes0(input, outputBuf);
            return outputBuf;
        }

        public byte[] ProcessBytes(byte[] input, int inOff, int length)
        {
            CheckState();
            CheckInput(input, inOff, length);
        
            var outputBuf = new byte[GetUpdateOutputSize(length)];
            ProcessBytes0(input.AsSpan(inOff, length), outputBuf);
            return outputBuf;
        }

        public int ProcessBytes(byte[] input, byte[] output, int outOff)
        {
            CheckState();
            CheckInput(input);
        
            return ProcessBytes0(input, output.AsSpan(outOff));
        }

        public int ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff)
        {
            CheckState();
            CheckInput(input, inOff, length);
        
            return ProcessBytes0(input.AsSpan(inOff, length), output.AsSpan(outOff));
        }

        public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            CheckState();
            CheckInput(input);
        
            return ProcessBytes0(input, output);
        }
    
        public byte[] DoFinal()
        {
            CheckState();
            CheckInput(ReadOnlySpan<byte>.Empty, true);
        
            var output = new byte[GetOutputSize(0)];
        
            DoFinal(output, 0);

            return output;
        }
    
        public byte[] DoFinal(byte[] input)
        {
            CheckState();
            CheckInput(input, true);

            var output = new byte[GetOutputSize(input.Length)];
    
            DoFinal(input.AsSpan(), output.AsSpan());

            return output;
        }

        public byte[] DoFinal(byte[] input, int inOff, int length)
        {
            CheckState();
            CheckInput(input, inOff, length, true);

            var output = new byte[GetOutputSize(length)];

            DoFinal(input.AsSpan(inOff, length), output.AsSpan());

            return output;
        }

        public int DoFinal(byte[] output, int outOff)
        {
            CheckState();
            CheckInput(ReadOnlySpan<byte>.Empty, true);
        
            // 这里不检查 output 和 outOff 是否满足输出缓冲区大小的原因是 DoFinal(Span<byte> output) 会执行检查的.
            // 考虑到调用这个方法不会处理传入新的数据, 因此不会提前检查.
        
            return DoFinal(output.AsSpan(outOff));
        }

        public int DoFinal(byte[] input, byte[] output, int outOff)
        {
            CheckState();
            CheckInput(input, true);

            // 这里不检查 output 和 outOff 是否满足输出缓冲区大小的原因是 DoFinal(Span<byte> input, Span<byte> output) 会执行检查的.
            // 考虑到调用这个方法不会处理传入新的数据, 因此不会提前检查.

            return DoFinal(input.AsSpan(), output.AsSpan(outOff));
        }

        public int DoFinal(byte[] input, int inOff, int length, byte[] output, int outOff)
        {
            CheckState();
            CheckInput(input, inOff, length, true);

            if (output.Length - outOff < GetOutputSize(length))
            {
                throw new ArgumentException("The provided output array is too small.", nameof(output));
            }

            return DoFinal(input.AsSpan(inOff, length), output.AsSpan(outOff));
        }

        public int DoFinal(Span<byte> output)
        {
            CheckState();
            CheckInput(ReadOnlySpan<byte>.Empty, true);
        
            if (output.Length < GetOutputSize(0))
            {
                throw new ArgumentException("The provided output array is too small.", nameof(output));
            }

            if (_unhandledBufferLength == 0)
            {
                Reset();
                return 0;
            }
            if (_unhandledBufferLength < 16)
            {
                throw new ArgumentException(
                    $"XTS data unit length ({_unhandledBufferLength} bytes) " +
                    "cannot be less than 16 bytes.");
            }
            if (_unhandledBufferLength == 16)
            {
                Span<byte> inputBlock = stackalloc byte[16];
                try
                {
                    _unhandledBuffer.AsSpan(0, 16).CopyTo(inputBlock);
                    ProcessXtsBlock(inputBlock, output);
                    Reset();
                    return 16;
                }
                finally
                {
                    XtsUtils.SecureWipe(inputBlock);
                }
            }

            // Tn-1
            Span<byte> tweakN1 = stackalloc byte[16];
            _tweakGenerator.GetTweakAndMove(tweakN1);
            // Tn
            Span<byte> tweakN = stackalloc byte[16];
            _tweakGenerator.CurrentTweak.CopyTo(tweakN);

            Span<byte> pn1Block = stackalloc byte[16];
            Span<byte> pnBlock = stackalloc byte[_unhandledBufferLength - 16];
        
            Span<byte> tempC = stackalloc byte[16];
            Span<byte> pnPaddedBlock = stackalloc byte[16];

            var finalOutputLength = _unhandledBufferLength;
            try {
                _unhandledBuffer.AsSpan(0, 16).CopyTo(pn1Block);
                _unhandledBuffer.AsSpan(16, pnBlock.Length).CopyTo(pnBlock);

                if (_forEncryption)
                {
                    Span<byte> cn = stackalloc byte[pnBlock.Length];
                    Span<byte> stolenData = stackalloc byte[16 - pnBlock.Length];

                    try
                    {
                        // Pre handle Pn-1
                        XtsUtils.XorBlock(pn1Block, tweakN1);
                        ProcessAesBlock(pn1Block, tempC);
                        XtsUtils.XorBlock(tempC, tweakN1);
                        // 到这里, tempC 是 Cn-1

                        // Steal
                        tempC[..cn.Length].CopyTo(cn);
                        tempC[pnBlock.Length..].CopyTo(stolenData);
                        // stolenData 是被窃取到 Pn 的数据.
                        // 到此 Cn 已经形成(下称 C'n), cn 的数据是 Cn-1 前 Cn.length 长度的数据.

                        // Pn handle
                        pnBlock.CopyTo(pnPaddedBlock);
                        stolenData.CopyTo(pnPaddedBlock[pnBlock.Length..]);
                        // 这里拼接出新的 Pn 数据, 也就是 P'n

                        // 对 P'n 加密, 得到 C'n 后将其设为 C'n-1, 完成最后一个完整块的加密.
                        XtsUtils.XorBlock(pnPaddedBlock, tweakN);
                        ProcessAesBlock(pnPaddedBlock, tempC);
                        XtsUtils.XorBlock(tempC, tweakN);

                        // 最后将 C'n-1 写到原本 Cn-1 的位置, 然后将 C'n 写到 Cn 的位置.
                        tempC.CopyTo(output);
                        cn.CopyTo(output[16..]);
                    }
                    finally
                    {
                        XtsUtils.SecureWipe(cn);
                        XtsUtils.SecureWipe(stolenData);
                    }
                }
                else
                {
                    Span<byte> cn1Output = stackalloc byte[16];

                    try
                    {
                        // 解密 Cn-1 得到 PnPadded, 此时拿到 P'n-1, 但是还没做窃密文处理.
                        XtsUtils.XorBlock(pn1Block, tweakN);
                        ProcessAesBlock(pn1Block, pnPaddedBlock);
                        XtsUtils.XorBlock(pnPaddedBlock, tweakN);

                        // 从 PnPadded 分离 Pn
                        pnPaddedBlock[..pnBlock.Length].CopyTo(output[16..]);

                        // 拼凑 Cn-1 并解密.
                        // 这里复用 pnPaddedBlock 使其成为 Cn-1
                        pnBlock.CopyTo(pnPaddedBlock[..pnBlock.Length]);
                    
                        // 到这里解密 Cn-1 得到 Pn-1.
                        XtsUtils.XorBlock(pnPaddedBlock, tweakN1);
                        ProcessAesBlock(pnPaddedBlock, cn1Output);
                        XtsUtils.XorBlock(cn1Output, tweakN1);

                        cn1Output.CopyTo(output[..16]);
                    }
                    finally
                    {
                        XtsUtils.SecureWipe(cn1Output);
                    }
                }
            
                Reset();
            } 
            finally 
            {
                XtsUtils.SecureWipe(pn1Block);
                XtsUtils.SecureWipe(pnBlock);
                XtsUtils.SecureWipe(tweakN1);
                XtsUtils.SecureWipe(tweakN);
                XtsUtils.SecureWipe(tempC);
                XtsUtils.SecureWipe(pnPaddedBlock);
            }
        
            return finalOutputLength;
        }

        public int DoFinal(ReadOnlySpan<byte> input, Span<byte> output)
        {
            CheckState();
            CheckInput(input, true);

            if (output.Length < GetOutputSize(input.Length))
            {
                throw new ArgumentException($"The provided output array is too small. " +
                                            $"(Require Buffer Size: {GetOutputSize(input.Length)}, actual buffer size: {output.Length}, unhandled buffer length: {_unhandledBufferLength})", nameof(output));
            }

            var middleOutputLength = ProcessBytes0(input, output);

            var finalOutputLength = DoFinal(output[middleOutputLength..]);

            return middleOutputLength + finalOutputLength;
        }

        public string AlgorithmName => "AES/XTS";
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }
        
            _dataEncEngine.Dispose();
        
            XtsUtils.SecureWipe(_unhandledBuffer);
            _parameters = null;
        
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}