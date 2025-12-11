namespace LamGC.AES_XTS
{
    public class XtsAesCipherParameters
    {
    
        public XtsAesMode Mode { get; private set; }
    
        public byte[] Key1 { get; private set; }
        public byte[] Key2 { get; private set; }

        public ulong SectorSize { get; private set; }
    
        /// <summary>
        /// 64 位扇区索引 (当 SectorIndex128 为 null 时使用).
        /// </summary>
        public ulong SectorIndex { get; private set; }

        /// <summary>
        /// 构造 AES-XTS 的加解密参数设定.
        /// </summary>
        /// <param name="mode">Cipher 加密模式, 参阅 XtsAESMode 说明.</param>
        /// <param name="dataEncryptKey">数据加解密密钥, 即 K1. 注意, K1 最好不要与 K2 相同, 否则会极大降低 AES-XTS 安全性.</param>
        /// <param name="tweakCalcKey">Tweak 值生成密钥, 即 K2. 注意, K2 最好不要与 K1 相同, 否则会极大降低 AES-XTS 安全性.</param>
        /// <param name="sectorSize">扇区大小, 必须是 16 的倍数(符合 AES 块大小).</param>
        /// <param name="sectorIndex">本次处理起始的扇区索引, 起始值为 0.</param>
        /// <exception cref="ArgumentException">当扇区大小不是 16 的倍数时抛出.</exception>
        public XtsAesCipherParameters(XtsAesMode mode, byte[] dataEncryptKey, byte[] tweakCalcKey, ulong sectorSize,
            ulong sectorIndex = 0)
        {
            if (sectorSize < 16)
            {
                throw new ArgumentException("The sector size must be greater than or equal to 16 bytes.");
            }
        
            Mode = mode;
        
            Key1 = dataEncryptKey;
            Key2 = tweakCalcKey;
        
            SectorSize = sectorSize;
            SectorIndex = sectorIndex;
        }
    }

    public enum XtsAesMode
    {
        /// <summary>
        /// 连续加解密模式.
        /// </summary>
        /// <remarks>
        /// 处于该模式下, Cipher 将根据设定的扇区大小, 为多段数据连续进行加密.
        /// 此时 SectorIndex 为起始扇区号.
        /// </remarks>
        Continuous,
        /// <summary>
        /// 独立加解密模式.
        /// </summary>
        /// <remarks>
        /// 处于该模式下, Cipher 会将传入的数据视为第 SectorIndex 个扇区的完整数据, 并为其单独加解密.
        /// </remarks>
        Independent
    }
}
