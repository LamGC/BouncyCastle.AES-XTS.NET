namespace LamGC.BouncyCastle.AES_XTS.Tests;

/// <summary>
/// GF(2^128) 乘以 α 运算测试.
/// 验证 MultiplyByAlpha 实现是否符合 IEEE P1619 标准.
/// </summary>
public abstract class MultiplyByAlphaTestBase
{
    /// <summary>
    /// 测试无溢出情况：最高位为 0，只需要左移.
    /// </summary>
    [Fact]
    public void MultiplyByAlpha_NoOverflow_ShouldShiftLeft()
    {
        // 输入：最高位为 0
        var input = Convert.FromHexString("01000000000000000000000000000000");
        var expected = Convert.FromHexString("02000000000000000000000000000000");

        var result = CallMultiplyByAlpha(input, 1);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// 测试有溢出情况：最高位为 1，需要 XOR 0x87.
    /// </summary>
    [Fact]
    public void MultiplyByAlpha_WithOverflow_ShouldShiftLeftAndXor()
    {
        // 输入：tweak[15] 的最高位为 1
        var input = Convert.FromHexString("00000000000000000000000000000080");
        // 预期：左移后 XOR 0x87 在 byte[0]
        var expected = Convert.FromHexString("87000000000000000000000000000000");

        var result = CallMultiplyByAlpha(input, 1);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// 测试全 1 输入的溢出情况.
    /// </summary>
    [Fact]
    public void MultiplyByAlpha_AllOnes_ShouldOverflowCorrectly()
    {
        var input = Convert.FromHexString("ffffffffffffffffffffffffffffffff");
        // 计算结果验证：
        // 1. 左移：每个字节都是 0xFF，最高位都是1，所以都需要进位
        // 2. 0xFF << 1 = 0xFE (最高位溢出成为进位)，加上上一字节的进位变成 0xFF
        // 3. 但最后一字节(byte[15])的溢出会导致 XOR 0x87
        // 实际计算：全部变成 0xFF，然后 byte[0] XOR 0x87 = 0x78
        // 但实际上 0xFF << 1 | carry = (0xFE | 1) = 0xFF for all bytes except first
        // For byte[0]: 0xFF << 1 = 0xFE, no previous carry, then XOR 0x87 = 0x79
        var result = CallMultiplyByAlpha(input, 1);

        Assert.NotEqual(input, result);
        Assert.Equal(16, result.Length);
        Assert.Equal((byte)(0xFE ^ 0x87), result[0]);
        
        for (var i = 1; i < 16; i++)
        {
            Assert.Equal((byte)0xFF, result[i]);
        }
    }

    /// <summary>
    /// 测试全零输入.
    /// </summary>
    [Fact]
    public void MultiplyByAlpha_AllZeros_ShouldRemainZero()
    {
        var input = new byte[16];
        var expected = new byte[16];

        var result = CallMultiplyByAlpha(input, 1);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// 测试连续乘法的正确性.
    /// </summary>
    [Fact]
    public void MultiplyByAlpha_ConsecutiveMultiplications_ShouldBeCorrect()
    {
        // 从 1 开始连续乘以 α
        var value = new byte[16];
        value[0] = 0x01;

        // α^1 = 0x02
        var alpha1 = CallMultiplyByAlpha(value, 1);
        Assert.Equal((byte)0x02, alpha1[0]);

        // α^2 = 0x04
        var alpha2 = CallMultiplyByAlpha(alpha1, 1);
        Assert.Equal((byte)0x04, alpha2[0]);

        // α^3 = 0x08
        var alpha3 = CallMultiplyByAlpha(alpha2, 1);
        Assert.Equal((byte)0x08, alpha3[0]);

        // α^7 = 0x80
        var alpha7 = alpha3;
        alpha7 = CallMultiplyByAlpha(alpha7, 4);
        Assert.Equal((byte)0x80, alpha7[0]);

        // α^8 应该在 byte[1] 位置
        var alpha8 = CallMultiplyByAlpha(alpha7, 1);
        Assert.Equal((byte)0x00, alpha8[0]);
        Assert.Equal((byte)0x01, alpha8[1]);
    }

    /// <summary>
    /// 测试 Little-Endian 字节序.
    /// IEEE P1619 使用 Little-Endian 表示.
    /// </summary>
    [Fact]
    public void MultiplyByAlpha_LittleEndianByteOrder_ShouldBeCorrect()
    {
        // 在 Little-Endian 中，最低有效字节在 byte[0]
        // 0x01 在 byte[0] 表示 α^0 = 1
        var one = new byte[16];
        one[0] = 0x01;

        // 乘以 α 后应该变成 0x02
        var alpha = CallMultiplyByAlpha(one, 1);
        Assert.Equal((byte)0x02, alpha[0]);
        for (int i = 1; i < 16; i++)
        {
            Assert.Equal((byte)0x00, alpha[i]);
        }
    }

    /// <summary>
    /// 测试跨字节的进位.
    /// </summary>
    [Fact]
    public void MultiplyByAlpha_CarryAcrossBytes_ShouldBeCorrect()
    {
        // 0x80 在 byte[0]，左移后应该进位到 byte[1]
        var input = new byte[16];
        input[0] = 0x80;

        var result = CallMultiplyByAlpha(input, 1);

        Assert.Equal((byte)0x00, result[0]);
        Assert.Equal((byte)0x01, result[1]);
    }

    /// <summary>
    /// 测试多字节进位链.
    /// </summary>
    [Fact]
    public void MultiplyByAlpha_CarryChain_ShouldPropagateCorrectly()
    {
        // 所有字节的最高位都是 1，应该形成进位链
        var input = Convert.FromHexString("80808080808080808080808080808080");
        // 左移后：01010101...，因为有溢出还要 XOR 0x87
        var expected = Convert.FromHexString("87010101010101010101010101010101");

        var result = CallMultiplyByAlpha(input, 1);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// 验证 α^128 = α^128 mod p(x) 的周期性（部分验证）.
    /// </summary>
    [Fact]
    public void MultiplyByAlpha_FieldPrimitive_ShouldHaveCorrectOrder()
    {
        // 在 GF(2^128) 中，α 是 x 的根
        // 不可约多项式是 x^128 + x^7 + x^2 + x + 1
        var value = new byte[16];
        value[0] = 0x01;

        // 连续乘 128 次后验证结果不是 1（因为真正的周期是 2^128 - 1）
        value = CallMultiplyByAlpha(value, 128);

        var one = new byte[16];
        one[0] = 0x01;

        Assert.NotEqual(one, value);
    }

    #region 实际 MultiplyByAlpha 调用

    protected abstract byte[] CallMultiplyByAlpha(byte[] input, ulong blockIndex);

    #endregion
}

public class StandardMultiplyByAlphaTests : MultiplyByAlphaTestBase
{
    protected override byte[] CallMultiplyByAlpha(byte[] input, ulong blockIndex)
    {
        var result = new byte[16];
        Array.Copy(input, result, 16);
        
        for (ulong i = 0; i < blockIndex; i++)
        {
            AbstractXtsTweakGenerator.MultiplyByAlpha(result);
        }
        
        return result;
    }
}

public class OptimizedMultiplyByAlphaTests : MultiplyByAlphaTestBase
{
    protected override byte[] CallMultiplyByAlpha(byte[] input, ulong blockIndex)
    {
        var result = new byte[16];
        Array.Copy(input, result, 16);
        
        AbstractXtsTweakGenerator.MultiplyByAlphaFast(result, blockIndex);
        
        return result;
    }
}
