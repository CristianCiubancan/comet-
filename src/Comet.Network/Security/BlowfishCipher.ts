// namespace Comet.Network.Security
// {
//     using System;
//     using System.Text;
//     using System.Runtime.CompilerServices;
//     using Comet.Core.Mathematics;

//     /// <summary>
//     /// This Blowfish cipher is implemented in CFB64 mode for client interoperability on
//     /// the game server, and replaces the legacy <see cref="TQCipher"/> previously used
//     /// by patches 5017 and below. This class uses the reference implementation of
//     /// Blowfish, which uses a key size of 576 bits rather than the standard 448 bits.
//     /// </summary>
//     public sealed class BlowfishCipher : ICipher
//     {
//         // Constants and static properties
//         public static readonly BlowfishCipher Default;
//         public const int BlockSize = 8;
//         private const int KeySize = 72;
//         private const int Rounds = 16;
//         private const string DefaultSeed = "DR654dt34trg4UI6";

//         private static readonly uint[] PInit = new uint[18] {
//             0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
//             0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
//             0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b
//         };
//         private static readonly uint[] SInit = new uint[4 * 256] {

//         };

//         // Local fields and properties
//         public byte[] DecryptionIV { get; private set; }
//         public byte[] EncryptionIV { get; private set; }
//         public uint[] P { get; private set; }
//         public uint[] S { get; private set; }
//         private int DecryptCount, EncryptCount;

//         /// <summary>Create a default instance of Blowfish to copy from.</summary>
//         static BlowfishCipher()
//         {
//             BlowfishCipher.Default = new BlowfishCipher();
//         }

//         /// <summary>
//         /// Instantiates a new instance of <see cref="BlowfishCipher"/> and generates
//         /// keys using the client's shared secret seed. Keys should be regenerated after
//         /// the DH Key Exchange has established a new shared secret.
//         /// </summary>
//         /// <param name="seed">Shared secret seed for generating keys</param>
//         public BlowfishCipher(string seed = BlowfishCipher.DefaultSeed)
//         {
//             this.DecryptionIV = new byte[BlowfishCipher.BlockSize];
//             this.EncryptionIV = new byte[BlowfishCipher.BlockSize];
//             this.DecryptCount = 0;
//             this.EncryptCount = 0;

//             this.GenerateKeys(new object[] { Encoding.ASCII.GetBytes(seed) });
//         }

//         /// <summary>
//         /// Instantiates a new instance of <see cref="BlowfishCipher"/> without
//         /// generating new keys. Instead, keys will be copied from the specified cipher
//         /// instance which has already generated keys based on a shared secret.
//         /// </summary>
//         /// <param name="copy">The cipher to copy keys from</param>
//         public BlowfishCipher(BlowfishCipher copy)
//         {
//             this.DecryptionIV = (byte[])copy.DecryptionIV.Clone();
//             this.EncryptionIV = (byte[])copy.EncryptionIV.Clone();
//             this.DecryptCount = copy.DecryptCount;
//             this.EncryptCount = copy.EncryptCount;

//             this.P = copy.P.Clone() as uint[];
//             this.S = copy.S.Clone() as uint[];
//         }

//         /// <summary>
//         /// The key schedule for Blowfish can be time consuming to generate. The server
//         /// should optimize around calls to generate keys. When providing an array of
//         /// seeds, only the first seed will be used to generate keys.
//         /// </summary>
//         /// <param name="seeds">An array of seeds used to generate keys</param>
//         public void GenerateKeys(object[] seeds)
//         {
//             // Initialize key buffers
//             var seedBuffer = seeds[0] as byte[];
//             if (seedBuffer.Length > BlowfishCipher.KeySize)
//                 Array.Resize(ref seedBuffer, BlowfishCipher.KeySize);

//             this.P = BlowfishCipher.PInit.Clone() as uint[];
//             this.S = BlowfishCipher.SInit.Clone() as uint[];

//             // Generate keys
//             for (uint i = 0, x = 0; i < this.P.Length; i++)
//             {
//                 uint rv = seedBuffer[x]; x = (uint)((x + 1) % seedBuffer.Length);
//                 rv = (rv << 8) | seedBuffer[x]; x = (uint)((x + 1) % seedBuffer.Length);
//                 rv = (rv << 8) | seedBuffer[x]; x = (uint)((x + 1) % seedBuffer.Length);
//                 rv = (rv << 8) | seedBuffer[x]; x = (uint)((x + 1) % seedBuffer.Length);
//                 this.P[i] ^= rv;
//             }

//             uint[] block = new uint[BlowfishCipher.BlockSize / sizeof(uint)];
//             for (int i = 0; i < this.P.Length; )
//             {
//                 this.EncipherBlock(block);
//                 this.P[i++] = block[0];
//                 this.P[i++] = block[1];
//             }

//             for (int i = 0; i < this.S.Length; )
//             {
//                 this.EncipherBlock(block);
//                 this.S[i++] = block[0];
//                 this.S[i++] = block[1];
//             }
//         }

//         /// <summary>Sets the IVs of the cipher.</summary>
//         /// <param name="decryptionIV">Decryption IV from client key exchange</param>
//         /// <param name="encryptionIV">Encryption IV from client key exchange</param>
//         public void SetIVs(byte[] decryptionIV, byte[] encryptionIV)
//         {
//             this.DecryptionIV = (byte[])decryptionIV.Clone();
//             this.EncryptionIV = (byte[])encryptionIV.Clone();
//             this.DecryptCount = 0;
//             this.EncryptCount = 0;
//         }

//         /// <summary>
//         /// Decrypts bytes using cipher feedback mode. The source and destination may be
//         /// the same slice, but otherwise should not overlap.
//         /// </summary>
//         /// <param name="src">Source span that requires decrypting</param>
//         /// <param name="dst">Destination span to contain the decrypted result</param>
//         public void Decrypt(Span<byte> src, Span<byte> dst)
//         {
//             uint[] block = new uint[2];
//             for (int i = 0; i < src.Length; i++)
//             {
//                 if (this.DecryptCount == 0)
//                 {
//                     block[0] = this.n21(this.DecryptionIV, 0);
//                     block[1] = this.n21(this.DecryptionIV, 4);
//                     this.EncipherBlock(block);
//                     this.n12(this.DecryptionIV, 0, block[0]);
//                     this.n12(this.DecryptionIV, 4, block[1]);
//                 }

//                 byte tmp = this.DecryptionIV[this.DecryptCount];
//                 this.DecryptionIV[this.DecryptCount] = src[i];
//                 dst[i] = (byte)(src[i] ^ tmp);
//                 this.DecryptCount = (this.DecryptCount + 1) & (BlowfishCipher.BlockSize - 1);
//             }
//         }

//         /// <summary>
//         /// Encrypts bytes using cipher feedback mode. The source and destination may be
//         /// the same slice, but otherwise should not overlap.
//         /// </summary>
//         /// <param name="src">Source span that requires encrypting</param>
//         /// <param name="dst">Destination span to contain the encrypted result</param>
//         public void Encrypt(Span<byte> src, Span<byte> dst)
//         {
//             uint[] block = new uint[2];
//             for (int i = 0; i < src.Length; i++)
//             {
//                 if (this.EncryptCount == 0)
//                 {
//                     block[0] = this.n21(this.EncryptionIV, 0);
//                     block[1] = this.n21(this.EncryptionIV, 4);
//                     this.EncipherBlock(block);
//                     this.n12(this.EncryptionIV, 0, block[0]);
//                     this.n12(this.EncryptionIV, 4, block[1]);
//                 }

//                 dst[i] = (byte)(src[i] ^ this.EncryptionIV[this.EncryptCount]);
//                 this.EncryptionIV[this.EncryptCount] = dst[i];
//                 this.EncryptCount = (this.EncryptCount + 1) & (BlowfishCipher.BlockSize - 1);
//             }
//         }

//         /// <summary>
//         /// Function F is Blowfish's one-way function for achieving non-linearity with
//         /// its substitution boxes without requiring a massive lookup array. Each input
//         /// is broken up into 4 bytes which is used as indexes to fetch 32-bit numbers
//         /// from the different S boxes.
//         /// </summary>
//         /// <param name="x">Input from the encipher round</param>
//         /// <returns>((Sa + Sb) ^ Sc) + Sd, S being the substitution per byte.</returns>
//         [MethodImpl(MethodImplOptions.AggressiveInlining)]
//         private uint F(uint x) =>
//             (((this.S[((x >> 24) & 0xFF)] + this.S[0x100 + ((x >> 16) & 0xFF)])
//              ^ this.S[0x200 + ((x >> 8) & 0xFF)]) + this.S[0x300 + ((x) & 0xFF)])
//              & 0xFFFFFFFF;

//         /// <summary>
//         /// Swaps the endianness and converts data types for block operations.
//         /// </summary>
//         /// <param name="iv">IV depending on the direction of the cipher</param>
//         /// <param name="x">Index used to read from the IV buffer</param>
//         /// <returns>An unsigned integer representing a side of the block.</returns>
//         private uint n21(byte[] iv, int x)
//         {
//             uint l = (uint)(iv[x] << 24);
//             l |= (uint)(iv[x + 1] << 16);
//             l |= (uint)(iv[x + 2] << 8);
//             l |= (uint)(iv[x + 3]);
//             return l;
//         }

//         /// <summary>
//         /// Converts on half of the results of a block operation back to bytes.
//         /// </summary>
//         /// <param name="iv">IV depending on the direction of the cipher</param>
//         /// <param name="x">Index used to write to the IV buffer</param>
//         /// <param name="v">Value from the block operation results.</param>
//         private void n12(byte[] iv, int x, uint v)
//         {
//             iv[x] = (byte)((v >> 24) & 0xFF);
//             iv[x + 1] = (byte)((v >> 16) & 0xFF);
//             iv[x + 2] = (byte)((v >> 8) & 0xFF);
//             iv[x + 3] = (byte)((v) & 0xFF);
//         }

//         /// <summary>
//         /// Enciphers a block of plaintext into ciphertext. If the cipher is used in
//         /// cipher feedback mode, then this method is also utilized for decrypting
//         /// ciphertext into plaintext.
//         /// </summary>
//         /// <param name="block">A block of two 32-bit unsigned integers</param>
//         private void EncipherBlock(uint[] block)
//         {
//             uint lv = block[0];
//             uint rv = block[1];

//             lv ^= this.P[0];
//             for (uint i = 1; i <= BlowfishCipher.Rounds; i++)
//             {
//                 rv ^= this.P[i];
//                 rv ^= this.F(lv);
//                 lv.Swap(ref rv);
//             }

//             rv ^= this.P[BlowfishCipher.Rounds + 1];
//             block[0] = rv & 0xFFFFFFFF;
//             block[1] = lv & 0xFFFFFFFF;
//         }
//     }
// }

class BlowfishCipher {}
