// SPDX-FileCopyrightText: 2023 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using System;
using System.Diagnostics.CodeAnalysis;
using Nethermind.Core;
using Nethermind.Core.Crypto;
using Nethermind.Core.Extensions;
using Nethermind.Serialization.Rlp;

namespace Nethermind.Optimism;

[Rlp.Decoder(RlpDecoderKey.Trie)]
public class OptimismReceiptTrieDecoder() : OptimismReceiptMessageDecoder(true);

[Rlp.Decoder]
public class OptimismReceiptMessageDecoder(bool isEncodedForTrie = false, bool skipStateAndStatus = false) : IRlpStreamDecoder<TxReceipt>
{
    private readonly bool _skipStateAndStatus = skipStateAndStatus;
    public OptimismTxReceipt Decode(RlpStream rlpStream, RlpBehaviors rlpBehaviors = RlpBehaviors.None)
    {
        OptimismTxReceipt txReceipt = new();
        if (!rlpStream.IsSequenceNext())
        {
            rlpStream.SkipLength();
            txReceipt.TxType = (TxType)rlpStream.ReadByte();
        }

        int lastCheck = rlpStream.ReadSequenceLength() + rlpStream.Position;

        byte[] firstItem = rlpStream.DecodeByteArray();
        if (firstItem.Length == 1 && (firstItem[0] == 0 || firstItem[0] == 1))
        {
            txReceipt.StatusCode = firstItem[0];
            txReceipt.GasUsedTotal = (long)rlpStream.DecodeUBigInt();
        }
        else if (firstItem.Length is >= 1 and <= 4)
        {
            txReceipt.GasUsedTotal = (long)firstItem.ToUnsignedBigInteger();
        }
        else
        {
            txReceipt.PostTransactionState = firstItem.Length == 0 ? null : new Hash256(firstItem);
            txReceipt.GasUsedTotal = (long)rlpStream.DecodeUBigInt();
        }

        txReceipt.Bloom = rlpStream.DecodeBloom();

        int logEntriesCheck = rlpStream.ReadSequenceLength() + rlpStream.Position;

        int numberOfReceipts = rlpStream.PeekNumberOfItemsRemaining(logEntriesCheck);
        LogEntry[] entries = new LogEntry[numberOfReceipts];
        for (int i = 0; i < numberOfReceipts; i++)
        {
            entries[i] = Rlp.Decode<LogEntry>(rlpStream, RlpBehaviors.AllowExtraBytes);
        }
        txReceipt.Logs = entries;

        if (lastCheck > rlpStream.Position)
        {
            if (txReceipt.TxType == TxType.DepositTx && lastCheck > rlpStream.Position)
            {
                txReceipt.DepositNonce = rlpStream.DecodeUlong();

                if (lastCheck > rlpStream.Position)
                {
                    txReceipt.DepositReceiptVersion = rlpStream.DecodeUlong();
                }
            }
        }

        return txReceipt;
    }

    private (int Total, int Logs) GetContentLength(TxReceipt item, RlpBehaviors rlpBehaviors)
    {
        if (item is null)
        {
            return (0, 0);
        }

        int contentLength = 0;
        contentLength += Rlp.LengthOf(item.GasUsedTotal);
        contentLength += Rlp.LengthOf(item.Bloom);

        int logsLength = GetLogsLength(item);
        contentLength += Rlp.LengthOfSequence(logsLength);

        bool isEip658Receipts = (rlpBehaviors & RlpBehaviors.Eip658Receipts) == RlpBehaviors.Eip658Receipts;

        if (!_skipStateAndStatus)
        {
            contentLength += isEip658Receipts
                ? Rlp.LengthOf(item.StatusCode)
                : Rlp.LengthOf(item.PostTransactionState);
        }

        if (item.IsOptimismTxReceipt(out var opItem))
        {
            if (opItem.DepositNonce is not null && (opItem.DepositReceiptVersion is not null || !isEncodedForTrie))
            {
                contentLength += Rlp.LengthOf(opItem.DepositNonce);

                if (opItem.DepositReceiptVersion is not null)
                {
                    contentLength += Rlp.LengthOf(opItem.DepositReceiptVersion.Value);
                }
            }
        }

        return (contentLength, logsLength);
    }

    public static int GetLogsLength(TxReceipt item)
    {
        int logsLength = 0;
        for (var i = 0; i < item.Logs?.Length; i++)
        {
            logsLength += Rlp.LengthOf(item.Logs[i]);
        }

        return logsLength;
    }

    /// <summary>
    /// https://eips.ethereum.org/EIPS/eip-2718
    /// </summary>
    public int GetLength(TxReceipt item, RlpBehaviors rlpBehaviors)
    {
        (int Total, _) = GetContentLength(item, rlpBehaviors);
        int receiptPayloadLength = Rlp.LengthOfSequence(Total);

        bool isForTxRoot = (rlpBehaviors & RlpBehaviors.SkipTypedWrapping) == RlpBehaviors.SkipTypedWrapping;
        int result = item.TxType != TxType.Legacy
            ? isForTxRoot
                ? (1 + receiptPayloadLength)
                : Rlp.LengthOfSequence(1 + receiptPayloadLength) // Rlp(TransactionType || TransactionPayload)
            : receiptPayloadLength;
        return result;
    }

    public void Encode(RlpStream rlpStream, TxReceipt item, RlpBehaviors rlpBehaviors = RlpBehaviors.None)
    {
        if (item is null)
        {
            rlpStream.EncodeNullObject();
            return;
        }

        (int totalContentLength, int logsLength) = GetContentLength(item, rlpBehaviors);
        int sequenceLength = Rlp.LengthOfSequence(totalContentLength);

        if (item.TxType != TxType.Legacy)
        {
            if ((rlpBehaviors & RlpBehaviors.SkipTypedWrapping) == RlpBehaviors.None)
            {
                rlpStream.StartByteArray(sequenceLength + 1, false);
            }

            rlpStream.WriteByte((byte)item.TxType);
        }

        rlpStream.StartSequence(totalContentLength);
        if (!_skipStateAndStatus)
        {
            rlpStream.Encode(item.StatusCode);
        }

        rlpStream.Encode(item.GasUsedTotal);
        rlpStream.Encode(item.Bloom);

        rlpStream.StartSequence(logsLength);
        for (var i = 0; i < item.Logs?.Length; i++)
        {
            rlpStream.Encode(item.Logs[i]);
        }

        if (item.IsOptimismTxReceipt(out var opItem))
        {
            if (opItem.DepositNonce is not null && (opItem.DepositReceiptVersion is not null || !isEncodedForTrie))
            {
                rlpStream.Encode(opItem.DepositNonce.Value);

                if (opItem.DepositReceiptVersion is not null)
                {
                    rlpStream.Encode(opItem.DepositReceiptVersion.Value);
                }
            }
        }
    }

    TxReceipt IRlpStreamDecoder<TxReceipt>.Decode(RlpStream rlpStream, RlpBehaviors rlpBehaviors)
    {
        return Decode(rlpStream, rlpBehaviors);
    }
}

internal static class TxReceiptExt
{
    internal static bool IsOptimismTxReceipt(this TxReceipt item, [NotNullWhen(true)] out OptimismTxReceipt? opItem)
    {
        opItem = null;

        if (item.TxType != TxType.DepositTx)
        {
            return false;
        }

        if (item is not OptimismTxReceipt casted)
        {
            throw new InvalidCastException($"{nameof(TxReceipt)} of type {item.TxType} is not an instance of {nameof(OptimismTxReceipt)}");
        }

        opItem = casted;
        return true;
    }
}
