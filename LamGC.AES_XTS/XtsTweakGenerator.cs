using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace LamGC.AES_XTS
{
    public abstract class AbstractXtsTweakGenerator : IDisposable
    {
        // 128 bits
        protected const int AesBlockSize = 16;

        // 有限域 GF(2^128) 的乘法常量 0x87
        private const byte TweakConstant = 0x87;

        public const ulong FastTweakMathThreshold = 2048;

        private readonly Aes _tweakCipher;

        protected AbstractXtsTweakGenerator(byte[] tweakKey)
        {
            _tweakCipher = Aes.Create();
            _tweakCipher.Key = tweakKey;
            _tweakCipher.Mode = CipherMode.ECB;
            _tweakCipher.Padding = PaddingMode.None;
        }

        public void Dispose()
        {
            _tweakCipher.Dispose();
            _tweakCipher.Dispose();

            GC.SuppressFinalize(this);
        }

        protected void ProcessAesBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            _tweakCipher.TryEncryptEcb(input, output, PaddingMode.None, out _);
        }

        public static void MultiplyByAlpha(Span<byte> tweak)
        {
            var overflow = (tweak[15] & 0x80) != 0;
            byte carry = 0;
            for (var i = 0; i < AesBlockSize; i++)
            {
                var nextCarry = (byte)((tweak[i] >> 7) & 1);
                tweak[i] = (byte)((tweak[i] << 1) | carry);
                carry = nextCarry;
            }

            if (overflow)
            {
                tweak[0] ^= TweakConstant;
            }
        }

        /// <summary>
        /// 快速计算并更新 Tweak：Tweak = Tweak * (alpha^blockIndex)
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void MultiplyByAlphaFast(Span<byte> baseTweak, ulong blockIndex)
        {
            Span<byte> alphaCoefficient = stackalloc byte[AesBlockSize];
            GfPow2(blockIndex, alphaCoefficient);
            GfMultiply(baseTweak, alphaCoefficient);
        }

        /// <summary>
        /// GF(2^128) 原位乘法: a = a * b
        /// </summary>
        /// <param name="accumulatorAndA">既是输入 a，也是输出结果。计算开始时会被备份并清空用于累加。</param>
        /// <param name="b">乘数 b</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void GfMultiply(Span<byte> accumulatorAndA, ReadOnlySpan<byte> b)
        {
            Span<byte> tempA = stackalloc byte[AesBlockSize];
            accumulatorAndA.CopyTo(tempA);
            accumulatorAndA.Clear();

            for (var i = 0; i < AesBlockSize; i++)
            {
                var bByte = b[i];
                for (var bit = 0; bit < 8; bit++)
                {
                    if ((bByte & (1 << bit)) != 0)
                    {
                        XtsUtils.XorBlock(accumulatorAndA, tempA);
                    }

                    MultiplyByAlpha(tempA);
                }
            }
        }

        /// <summary>
        /// 快速幂: return (alpha ^ power) mod P(x)
        /// 复杂度: O(log power)
        /// </summary>
        public static void GfPow2(ulong power, Span<byte> result)
        {
            result[0] = 0x01;

            Span<byte> baseVal = stackalloc byte[AesBlockSize];
            baseVal[0] = 0x02;

            Span<byte> baseCopy = stackalloc byte[AesBlockSize];

            while (power > 0)
            {
                if ((power & 1) == 1)
                {
                    GfMultiply(result, baseVal);
                }

                if (power > 1)
                {
                    baseVal.CopyTo(baseCopy);
                    GfMultiply(baseVal, baseCopy);
                }

                power >>= 1;
            }
        }
    }

    public class XtsTweakGenerator : AbstractXtsTweakGenerator
    {
        public XtsTweakGenerator(byte[] tweakCalcKey) : base(tweakCalcKey)
        {
        }

        public byte[] CalculateTweak(ulong sectorIndex, ulong blockIndex)
        {
            Span<byte> sectorIndexBytes = stackalloc byte[16];
            BitConverter.TryWriteBytes(sectorIndexBytes, sectorIndex);
            try
            {
                return CalculateTweak(sectorIndexBytes, blockIndex);
            }
            finally
            {
                XtsUtils.SecureWipe(sectorIndexBytes);
            }
        }

        /// <summary>
        /// 无状态计算 XTS 模式下指定块的 Tweak 值 (Ti = E_K2(Sector Index) * alpha^blockIndex)。
        /// </summary>
        /// <param name="sectorIndex128">128 位扇区索引 (16 字节)</param>
        /// <param name="blockIndex">扇区内的块索引 i (从 0 开始)</param>
        /// <returns>16 字节的 Tweak Ti</returns>
        public byte[] CalculateTweak(ReadOnlySpan<byte> sectorIndex128, ulong blockIndex)
        {
            if (sectorIndex128.Length != AesBlockSize)
            {
                throw new ArgumentException("Sector index must be exactly 16 bytes.", nameof(sectorIndex128));
            }

            var t0 = new byte[AesBlockSize];
            ProcessAesBlock(sectorIndex128, t0);

            if (blockIndex <= FastTweakMathThreshold)
            {
                for (ulong i = 0; i < blockIndex; i++)
                {
                    MultiplyByAlpha(t0);
                }
            }
            else
            {
                MultiplyByAlphaFast(t0, blockIndex);
            }

            return t0;
        }
    }

    public class XtsTweakStatefulGenerator : AbstractXtsTweakGenerator, IDisposable
    {
        private readonly byte[] _currentBlockTweak = new byte[AesBlockSize];

        public XtsTweakStatefulGenerator(byte[] tweakCalcKey, ulong sectorSize, ulong startSectorIndex = 0,
            ulong startBlockIndex = 0) : base(tweakCalcKey)
        {
            Reset(sectorSize, startSectorIndex, startBlockIndex);
        }

        /// <summary>
        /// 当前 Generator 所使用的 SectorSize.
        /// </summary>
        public ulong SectorSize { get; private set; }

        /// <summary>
        /// 根据 SectorSize 计算得出的 Sector 内总共的加密块数量.
        /// </summary>
        public ulong TotalBlockCountInSector => (SectorSize + AesBlockSize - 1) / AesBlockSize;

        /// <summary>
        /// 当前 Tweak 所属的 SectorIndex.
        /// </summary>
        public ulong CurrentSectorIndex { get; private set; }

        /// <summary>
        /// 当前 Tweak 所指向的 Sector 内的 BlockIndex.
        /// </summary>
        /// <remarks>
        /// DataOffsetInSector = CurrentBlockIndex * 16
        /// </remarks>
        public ulong CurrentBlockIndex { get; private set; }

        /// <summary>
        /// 当前 Tweak 的 Span 只读视图.
        /// </summary>
        public ReadOnlySpan<byte> CurrentTweak => _currentBlockTweak;

        public new void Dispose()
        {
            base.Dispose();
            XtsUtils.SecureWipe(_currentBlockTweak);

            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// 使用新的参数重置 Generator, 并初始化 CurrentTweak 为 Reset 所指定 Block 的 Tweak.
        /// </summary>
        /// <param name="sectorSize">新的 SectorSize.</param>
        /// <param name="startSectorIndex">起始 SectorIndex, 这也是 Reset 后 CurrentTweak 的所属 SectorIndex.</param>
        /// <param name="startBlockIndex">第一个 Tweak 从 Sector 内的第几个 Block 开始, 这也是 Reset 后 CurrentTweak 的所属 BlockIndex.</param>
        /// <exception cref="ArgumentException">当 SectorSize 小于 16 字节时抛出该异常.</exception>
        /// <exception cref="ArgumentOutOfRangeException">当指定的 StartBlockIndex 超出 SectorSize 所允许的 TotalBlock 时抛出.</exception>
        public void Reset(ulong sectorSize, ulong startSectorIndex = 0, ulong startBlockIndex = 0)
        {
            if (sectorSize < 16)
            {
                throw new ArgumentException("The sector size must be greater than or equal to 16 bytes.");
            }

            SectorSize = sectorSize;

            if (startBlockIndex >= TotalBlockCountInSector)
            {
                throw new ArgumentOutOfRangeException(nameof(startBlockIndex),
                    "StartBlockIndex cannot be greater than TotalBlockCountInSector.");
            }

            CurrentSectorIndex = startSectorIndex;
            CurrentBlockIndex = startBlockIndex;

            RecalculateSectorStartTweak();
            if (startBlockIndex <= FastTweakMathThreshold)
            {
                // 由于 i 不干扰计算过程, 且能保证在不导致整数溢出的情况下减去下一次调用 GetNextTweak 的计算, 因此将 i 设置为 1 而不是 0.
                for (ulong i = 0; i < startBlockIndex; i++)
                {
                    MultiplyByAlpha(_currentBlockTweak);
                }
            }
            else
            {
                MultiplyByAlphaFast(_currentBlockTweak, startBlockIndex);
            }
        }

        /// <summary>
        /// 初始化 _currentBlockTweak.
        /// </summary>
        /// <remarks>
        /// 执行该方法后, Tweak 等于 tweak[_currentSectorIndex][0], 因此执行该方法时, _currentBlockIndex 应为 0, 或执行后, 依据 _currentBlockIndex 提前执行计算.
        /// </remarks>
        private void RecalculateSectorStartTweak()
        {
            Span<byte> sectorIndexBytes = stackalloc byte[16];
            BitConverter.TryWriteBytes(sectorIndexBytes, CurrentSectorIndex);
            ProcessAesBlock(sectorIndexBytes, _currentBlockTweak);
            XtsUtils.SecureWipe(sectorIndexBytes);
        }

        /// <summary>
        /// 更新并计算下一个 Block 的 Tweak.
        /// </summary>
        public void MoveNext()
        {
            MultiplyByAlpha(_currentBlockTweak);
            CurrentBlockIndex++;
            if (CurrentBlockIndex >= TotalBlockCountInSector)
            {
                CurrentBlockIndex = 0;
                CurrentSectorIndex++;

                RecalculateSectorStartTweak();
            }
        }

        /// <summary>
        /// 获取当前 Tweak 并使 Generator 更新并计算下一个块.
        /// </summary>
        /// <remarks>
        /// 注意, 通过本函数获取 Tweak 后, CurrentSectorIndex 和 CurrentBlockIndex 将跳转至下一个值.
        /// </remarks>
        /// <returns>返回当前的 Tweak 值.</returns>
        public byte[] GetTweakAndMove()
        {
            var current = CurrentTweak.ToArray();
            MoveNext();
            return current;
        }

        /// <summary>
        /// 获取当前 Tweak 并使 Generator 更新并计算下一个块.
        /// </summary>
        /// <remarks>
        /// 注意, 通过本函数获取 Tweak 后, CurrentSectorIndex 和 CurrentBlockIndex 将跳转至下一个值.
        /// </remarks>
        /// <returns>返回当前的 Tweak 值.</returns>
        public void GetTweakAndMove(Span<byte> tweakOutputBuffer)
        {
            CurrentTweak.CopyTo(tweakOutputBuffer);
            MoveNext();
        }
    }
}