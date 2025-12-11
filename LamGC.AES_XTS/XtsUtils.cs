using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

#if NET7_0_OR_GREATER
using System.Numerics;
using System.Runtime.Intrinsics;
#endif

namespace LamGC.AES_XTS
{
    public static class XtsUtils
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void XorBlock(Span<byte> dst, ReadOnlySpan<byte> src)
        {
#if NET7_0_OR_GREATER
            if (Vector128.IsHardwareAccelerated && dst.Length >= 16)
            {
                ref var dstRef = ref MemoryMarshal.GetReference(dst);
                ref var srcRef = ref MemoryMarshal.GetReference(src);

                var vDst = Vector128.LoadUnsafe(ref dstRef);
                var vSrc = Vector128.LoadUnsafe(ref srcRef);

                (vDst ^ vSrc).StoreUnsafe(ref dstRef);
                return;
            }
#endif

            var dstUlong = MemoryMarshal.Cast<byte, ulong>(dst);
            var srcUlong = MemoryMarshal.Cast<byte, ulong>(src);

            if (dstUlong.Length >= 2)
            {
                dstUlong[0] ^= srcUlong[0];
                dstUlong[1] ^= srcUlong[1];
                return;
            }

            for (var i = 0; i < dst.Length; i++)
            {
                dst[i] ^= src[i];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void SecureWipe(Span<byte> buffer)
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public static class XtsParameterValidators
    {
        
#if NET7_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ThrowIfNegative<T>(T value, [CallerArgumentExpression("value")] string? paramName = null) where T : INumberBase<T>
        {
            if (!T.IsNegative(value))
                return;
            throw new ArgumentOutOfRangeException(paramName, value, "must be positive.");
        }
#else
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ThrowIfNegative(int value, [CallerArgumentExpression("value")] string? paramName = null)
        {
            if (value >= 0)
                return;
            throw new ArgumentOutOfRangeException(paramName, value, "must be positive.");
        }
#endif
        
    }
    
}