using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace LamGC.BouncyCastle.AES_XTS;

public static class XtsUtils
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void XorBlock(Span<byte> dst, ReadOnlySpan<byte> src)
    {
        if (Vector128.IsHardwareAccelerated && dst.Length >= 16)
        {
            ref var dstRef = ref MemoryMarshal.GetReference(dst);
            ref var srcRef = ref MemoryMarshal.GetReference(src);

            var vDst = Vector128.LoadUnsafe(ref dstRef);
            var vSrc = Vector128.LoadUnsafe(ref srcRef);
            
            (vDst ^ vSrc).StoreUnsafe(ref dstRef);
            return;
        }

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
}