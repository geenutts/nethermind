// SPDX-FileCopyrightText: 2022 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using System;
using System.Numerics;
using Nethermind.Core;
using Nethermind.Core.Crypto;
using Nethermind.Core.Extensions;
using Nethermind.Core.Specs;
using Nethermind.Crypto;
using Nethermind.Evm;
using Nethermind.TxPool;
using Org.BouncyCastle.Utilities.Encoders;

namespace Nethermind.Consensus.Validators
{
    public class TxValidator : ITxValidator
    {
        private readonly ulong _chainIdValue;

        public TxValidator(ulong chainId)
        {
            _chainIdValue = chainId;
        }

        /* Full and correct validation is only possible in the context of a specific block
           as we cannot generalize correctness of the transaction without knowing the EIPs implemented
           and the world state (account nonce in particular ).
           Even without protocol change the tx can become invalid if another tx
           from the same account with the same nonce got included on the chain.
           As such we can decide whether tx is well formed but we also have to validate nonce
           just before the execution of the block / tx. */
        public bool IsWellFormed(Transaction transaction, IReleaseSpec releaseSpec)
        {
            // validate type before calculating intrinsic gas to avoid exception
            bool isTxTypeValid = ValidateTxType(transaction, releaseSpec);
            if (!isTxTypeValid)
            {
                Console.WriteLine("Tx type is invalid");
                return false;
            }

            /* This is unnecessarily calculated twice - at validation and execution times. */
            bool isGasLimitValid = transaction.GasLimit >= IntrinsicGasCalculator.Calculate(transaction, releaseSpec);

            if (!isGasLimitValid)
            {
                Console.WriteLine("Gas limit is not vlaid {0} < {1}", transaction.GasLimit, IntrinsicGasCalculator.Calculate(transaction, releaseSpec));
                return false;
            }
            /* if it is a call or a transfer then we require the 'To' field to have a value while for an init it will be empty */
            bool isSignatureValid = ValidateSignature(transaction.Signature, releaseSpec);


            if (!isSignatureValid)
            {
                Console.WriteLine("Signature is invalid");
                return false;
            }

            bool isChainIdValid = ValidateChainId(transaction);
            if (!isChainIdValid)
            {
                Console.WriteLine("Chain ID is invalid");
                return false;
            }
            bool is1559GasFieldsValid =     Validate1559GasFields(transaction, releaseSpec);
            if (!is1559GasFieldsValid)
            {
                Console.WriteLine("1559 Gas Fields are invalid");
                return false;
            }
            bool is3860RulesValid =    Validate3860Rules(transaction, releaseSpec);
            if (!is3860RulesValid)
            {
                Console.WriteLine("3860 rules are invalid");
                return false;
            }

            bool are4844FeildsValid = Validate4844Fields(transaction);

            if (!are4844FeildsValid)
            {
                Console.WriteLine("Tx4844Fields are invalid");
                return false;
            }

            return true;
        }

        private bool Validate3860Rules(Transaction transaction, IReleaseSpec releaseSpec)
        {
            bool aboveInitCode = transaction.IsContractCreation && releaseSpec.IsEip3860Enabled &&
                                 transaction.DataLength > releaseSpec.MaxInitCodeSize;
            return !aboveInitCode;
        }

        private bool ValidateTxType(Transaction transaction, IReleaseSpec releaseSpec)
        {
            switch (transaction.Type)
            {
                case TxType.Legacy:
                    return true;
                case TxType.AccessList:
                    return releaseSpec.UseTxAccessLists;
                case TxType.EIP1559:
                    return releaseSpec.IsEip1559Enabled;
                case TxType.Blob:
                    return releaseSpec.IsEip4844Enabled;
                default:
                    return false;
            }
        }

        private bool Validate1559GasFields(Transaction transaction, IReleaseSpec releaseSpec)
        {
            if (!releaseSpec.IsEip1559Enabled || !transaction.IsEip1559)
                return true;

            return transaction.MaxFeePerGas >= transaction.MaxPriorityFeePerGas;
        }

        private bool ValidateChainId(Transaction transaction)
        {
            switch (transaction.Type)
            {
                case TxType.Legacy:
                    return true;
                default:
                    return transaction.ChainId == _chainIdValue;
            }
        }

        private bool ValidateSignature(Signature? signature, IReleaseSpec spec)
        {
            if (signature is null)
            {
                return false;
            }

            BigInteger sValue = signature.SAsSpan.ToUnsignedBigInteger();
            BigInteger rValue = signature.RAsSpan.ToUnsignedBigInteger();

            if (sValue.IsZero || sValue >= (spec.IsEip2Enabled ? Secp256K1Curve.HalfN + 1 : Secp256K1Curve.N))
            {
                return false;
            }

            if (rValue.IsZero || rValue >= Secp256K1Curve.N - 1)
            {
                return false;
            }

            if (spec.IsEip155Enabled)
            {
                return (signature.ChainId ?? _chainIdValue) == _chainIdValue;
            }

            return !spec.ValidateChainId || signature.V is 27 or 28;
        }

        private static bool Validate4844Fields(Transaction transaction)
        {
            const int maxBlobsPerTransaction = 4;

            if (transaction.Type != TxType.Blob)
            {
                return true;
            }

            if (transaction.MaxFeePerDataGas is null ||
                transaction.BlobVersionedHashes is null ||
                transaction.BlobVersionedHashes?.Length > maxBlobsPerTransaction)
            {
                Console.WriteLine("MaxFeePerDataGas {0} BlobVersionedHashes {1} len(BlobVersionedHashes) {2}", transaction.MaxFeePerDataGas, transaction.BlobVersionedHashes, transaction.BlobVersionedHashes?.Length);
                return false;
            }

            if (transaction.BlobKzgs is not null)
            {
                Span<byte> hash = stackalloc byte[32];
                Span<byte> commitements = transaction.BlobKzgs;
                for (int i = 0, n = 0;
                     i < transaction.BlobVersionedHashes!.Length;
                     i++, n += Ckzg.Ckzg.BytesPerCommitment)
                {
                    if (!KzgPolynomialCommitments.TryComputeCommitmentV1(
                            commitements[n..(n + Ckzg.Ckzg.BytesPerCommitment)], hash) ||
                        !hash.SequenceEqual(transaction.BlobVersionedHashes![i]))
                    {
                        Console.WriteLine("Commitment to hash is the problem {0} vs {1}", Hex.ToHexString(hash.ToArray()), Hex.ToHexString(transaction.BlobVersionedHashes[i]));
                        return false;
                    }
                }
            }

            bool res = KzgPolynomialCommitments.AreProofsValid(transaction.Blobs,
                transaction.BlobKzgs, transaction.BlobProofs);
            if(!res)
            {
                Console.WriteLine("AreProofsValid = false");
                return false;
            }
            return true;
        }
    }
}
