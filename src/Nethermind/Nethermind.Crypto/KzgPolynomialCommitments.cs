// SPDX-FileCopyrightText: 2022 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using Nethermind.Crypto.Properties;
using Nethermind.Int256;

namespace Nethermind.Crypto;

public static class KzgPolynomialCommitments
{
    public static readonly UInt256 BlsModulus =
        UInt256.Parse("52435875175126190479447740508185965837690552500527637822603658699938581184513",
            System.Globalization.NumberStyles.Integer);

    public static readonly ulong FieldElementsPerBlob = 4096;

    private const byte KzgBlobHashVersionV1 = 1;
    private static IntPtr _ckzgSetup = IntPtr.Zero;

    private static readonly ThreadLocal<SHA256> _sha256 = new(SHA256.Create);

    private static readonly object _inititalizeLock = new();

    public static void Inititalize()
    {
        lock (_inititalizeLock)
        {
            if (_ckzgSetup != IntPtr.Zero)
            {
                return;
            }

            string tmpFilename = Path.GetTempFileName();
            using FileStream tmpFileStream = new(tmpFilename, FileMode.OpenOrCreate, FileAccess.Write);
            using TextWriter tmpFileWriter = new StreamWriter(tmpFileStream);
            tmpFileWriter.Write(Resources.kzg_trusted_setup);
            tmpFileWriter.Close();
            tmpFileStream.Close();
            _ckzgSetup = Ckzg.Ckzg.LoadTrustedSetup(tmpFilename);
            File.Delete(tmpFilename);
        }
    }

    /// <summary>
    ///
    /// </summary>
    /// <param name="commitment">Commitment to calculate hash from</param>
    /// <param name="hashBuffer">Holds the output, can safely contain any data before the call.</param>
    /// <returns>Result of the attempt</returns>
    /// <exception cref="ArgumentException"></exception>
    public static bool TryComputeCommitmentV1(ReadOnlySpan<byte> commitment, Span<byte> hashBuffer)
    {
        const int bytesPerHash = 32;

        if (commitment.Length != Ckzg.Ckzg.BytesPerCommitment)
        {
            throw new ArgumentException($"Commitment should be {Ckzg.Ckzg.BytesPerCommitment} bytes",
                nameof(commitment));
        }

        if (hashBuffer.Length != bytesPerHash)
        {
            throw new ArgumentException($"Commitment should be {bytesPerHash} bytes", nameof(hashBuffer));
        }

        if (_sha256.Value!.TryComputeHash(commitment, hashBuffer, out _))
        {
            hashBuffer[0] = KzgBlobHashVersionV1;
            return true;
        }

        return false;
    }

    public static bool VerifyProof(ReadOnlySpan<byte> commitment, ReadOnlySpan<byte> z, ReadOnlySpan<byte> y,
        ReadOnlySpan<byte> proof)
    {
        return Ckzg.Ckzg.VerifyKzgProof(commitment, z, y, proof, _ckzgSetup);
    }

    public static bool AreProofsValid(byte[] blobs, byte[] commitments, byte[] proofs)
    {
        return Ckzg.Ckzg.VerifyBlobKzgProofBatch(blobs, commitments, proofs, blobs.Length / Ckzg.Ckzg.BytesPerBlob,
            _ckzgSetup);
    }
}
