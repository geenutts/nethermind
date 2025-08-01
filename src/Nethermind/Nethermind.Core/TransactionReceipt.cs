// SPDX-FileCopyrightText: 2022 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using System;
using Nethermind.Core.Attributes;
using Nethermind.Core.Crypto;

namespace Nethermind.Core
{
    public class TxReceipt
    {
        private Bloom? _boom;

        public TxReceipt()
        {
        }

        public TxReceipt(TxReceipt other)
        {
            TxType = other.TxType;
            StatusCode = other.StatusCode;
            BlockNumber = other.BlockNumber;
            BlockHash = other.BlockHash;
            TxHash = other.TxHash;
            Index = other.Index;
            GasUsed = other.GasUsed;
            GasUsedTotal = other.GasUsedTotal;
            Sender = other.Sender;
            ContractAddress = other.ContractAddress;
            Recipient = other.Recipient;
            ReturnValue = other.ReturnValue;
            PostTransactionState = other.PostTransactionState;
            Bloom = other.Bloom;
            Logs = other.Logs;
            Error = other.Error;
        }

        /// <summary>
        /// EIP-2718 transaction type
        /// </summary>
        public TxType TxType { get; set; }

        /// <summary>
        ///     EIP-658
        /// </summary>
        public byte StatusCode { get; set; }
        public long BlockNumber { get; set; }
        public Hash256? BlockHash { get; set; }
        public Hash256? TxHash { get; set; }
        public int Index { get; set; }
        public long GasUsed { get; set; }
        public long GasUsedTotal { get; set; }
        public Address? Sender { get; set; }
        public Address? ContractAddress { get; set; }
        public Address? Recipient { get; set; }

        [Todo(Improve.Refactor, "Receipt tracer?")]
        public byte[]? ReturnValue { get; set; }

        /// <summary>
        ///     Removed in EIP-658
        /// </summary>
        public Hash256? PostTransactionState { get; set; }
        public Bloom? Bloom { get => _boom ?? CalculateBloom(); set => _boom = value; }
        public LogEntry[]? Logs { get; set; }
        public string? Error { get; set; }


        public Bloom CalculateBloom()
            => _boom = Logs?.Length == 0 ? Bloom.Empty : new Bloom(Logs);
    }

    public ref struct TxReceiptStructRef
    {
        /// <summary>
        /// EIP-2718 transaction type
        /// </summary>
        public TxType TxType { get; set; }

        /// <summary>
        ///     EIP-658
        /// </summary>
        public byte StatusCode { get; set; }
        public long BlockNumber { get; set; }
        public Hash256StructRef BlockHash;
        public Hash256StructRef TxHash;
        public int Index { get; set; }
        public long GasUsed { get; set; }
        public long GasUsedTotal { get; set; }
        public AddressStructRef Sender;
        public AddressStructRef ContractAddress;
        public AddressStructRef Recipient;

        [Todo(Improve.Refactor, "Receipt tracer?")]
        public Span<byte> ReturnValue;

        /// <summary>
        ///     Removed in EIP-658
        /// </summary>
        public Hash256StructRef PostTransactionState;

        public BloomStructRef Bloom;

        /// <summary>
        /// Rlp encoded logs
        /// </summary>
        public ReadOnlySpan<byte> LogsRlp { get; set; }

        public LogEntry[]? Logs { get; set; }

        public string? Error { get; set; }

        public TxReceiptStructRef(TxReceipt receipt)
        {
            TxType = receipt.TxType;
            StatusCode = receipt.StatusCode;
            BlockNumber = receipt.BlockNumber;
            BlockHash = (receipt.BlockHash ?? Keccak.Zero).ToStructRef();
            TxHash = (receipt.TxHash ?? Keccak.Zero).ToStructRef();
            Index = receipt.Index;
            GasUsed = receipt.GasUsed;
            GasUsedTotal = receipt.GasUsedTotal;
            Sender = (receipt.Sender ?? Address.Zero).ToStructRef();
            ContractAddress = (receipt.ContractAddress ?? Address.Zero).ToStructRef();
            Recipient = (receipt.Recipient ?? Address.Zero).ToStructRef();
            ReturnValue = receipt.ReturnValue;
            PostTransactionState = (receipt.PostTransactionState ?? Keccak.Zero).ToStructRef();
            Bloom = (receipt.Bloom ?? Core.Bloom.Empty).ToStructRef();
            Logs = receipt.Logs;
            LogsRlp = default;
            Error = receipt.Error;
        }
    }
}
