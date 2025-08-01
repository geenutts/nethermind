// SPDX-FileCopyrightText: 2022 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using System;
using System.Threading;
using Nethermind.Blockchain;
using Nethermind.Blockchain.BeaconBlockRoot;
using Nethermind.Blockchain.Blocks;
using Nethermind.Blockchain.Find;
using Nethermind.Blockchain.Receipts;
using Nethermind.Consensus.AuRa.Validators;
using Nethermind.Consensus.ExecutionRequests;
using Nethermind.Consensus.Processing;
using Nethermind.Consensus.Rewards;
using Nethermind.Consensus.Transactions;
using Nethermind.Consensus.Validators;
using Nethermind.Consensus.Withdrawals;
using Nethermind.Core;
using Nethermind.Core.Specs;
using Nethermind.Crypto;
using Nethermind.Evm.State;
using Nethermind.Evm.Tracing;
using Nethermind.Logging;
using Nethermind.TxPool;

namespace Nethermind.Consensus.AuRa
{
    public class AuRaBlockProcessor : BlockProcessor
    {
        private readonly ISpecProvider _specProvider;
        private readonly IBlockFinder _blockTree;
        private readonly AuRaContractGasLimitOverride? _gasLimitOverride;
        private readonly ContractRewriter? _contractRewriter;
        private readonly ITxFilter _txFilter;
        private readonly ILogger _logger;

        public AuRaBlockProcessor(ISpecProvider specProvider,
            IBlockValidator blockValidator,
            IRewardCalculator rewardCalculator,
            IBlockProcessor.IBlockTransactionsExecutor blockTransactionsExecutor,
            IWorldState stateProvider,
            IReceiptStorage receiptStorage,
            IBeaconBlockRootHandler beaconBlockRootHandler,
            ILogManager logManager,
            IBlockFinder blockTree,
            IWithdrawalProcessor withdrawalProcessor,
            IExecutionRequestsProcessor executionRequestsProcessor,
            IAuRaValidator? auRaValidator,
            ITxFilter? txFilter = null,
            AuRaContractGasLimitOverride? gasLimitOverride = null,
            ContractRewriter? contractRewriter = null)
            : base(
                specProvider,
                blockValidator,
                rewardCalculator,
                blockTransactionsExecutor,
                stateProvider,
                receiptStorage,
                beaconBlockRootHandler,
                new BlockhashStore(specProvider, stateProvider),
                logManager,
                withdrawalProcessor,
                executionRequestsProcessor)
        {
            _specProvider = specProvider;
            _blockTree = blockTree ?? throw new ArgumentNullException(nameof(blockTree));
            _logger = logManager?.GetClassLogger<AuRaBlockProcessor>() ?? throw new ArgumentNullException(nameof(logManager));
            _txFilter = txFilter ?? NullTxFilter.Instance;
            _gasLimitOverride = gasLimitOverride;
            _contractRewriter = contractRewriter;
            AuRaValidator = auRaValidator ?? new NullAuRaValidator();
            if (blockTransactionsExecutor is IBlockProductionTransactionsExecutor produceBlockTransactionsStrategy)
            {
                produceBlockTransactionsStrategy.AddingTransaction += OnAddingTransaction;
            }
        }

        public IAuRaValidator AuRaValidator { get; }

        protected override TxReceipt[] ProcessBlock(Block block, IBlockTracer blockTracer, ProcessingOptions options, IReleaseSpec spec, CancellationToken token)
        {
            ValidateAuRa(block);
            bool wereChanges = _contractRewriter?.RewriteContracts(block.Number, _stateProvider, spec) ?? false;
            if (wereChanges)
            {
                _stateProvider.Commit(spec, commitRoots: true);
            }
            AuRaValidator.OnBlockProcessingStart(block, options);
            TxReceipt[] receipts = base.ProcessBlock(block, blockTracer, options, spec, token);
            AuRaValidator.OnBlockProcessingEnd(block, receipts, options);
            Metrics.AuRaStep = block.Header?.AuRaStep ?? 0;
            return receipts;
        }

        // After PoS switch we need to revert to standard block processing, ignoring AuRa customizations
        protected TxReceipt[] PostMergeProcessBlock(Block block, IBlockTracer blockTracer, ProcessingOptions options, IReleaseSpec spec, CancellationToken token)
        {
            return base.ProcessBlock(block, blockTracer, options, spec, token);
        }

        // This validations cannot be run in AuraSealValidator because they are dependent on state.
        private void ValidateAuRa(Block block)
        {
            if (!block.IsGenesis)
            {
                ValidateGasLimit(block);
                ValidateTxs(block);
            }
        }

        private BlockHeader GetParentHeader(Block block) =>
            _blockTree.FindParentHeader(block.Header, BlockTreeLookupOptions.None)!;

        private void ValidateGasLimit(Block block)
        {
            BlockHeader parentHeader = GetParentHeader(block);
            if (_gasLimitOverride?.IsGasLimitValid(parentHeader, block.GasLimit, out long? expectedGasLimit) == false)
            {
                string reason = $"Invalid gas limit, expected value from contract {expectedGasLimit}, but found {block.GasLimit}";
                if (_logger.IsWarn) _logger.Warn($"Proposed block is not valid {block.ToString(Block.Format.FullHashAndNumber)}. {reason}.");
                throw new InvalidBlockException(block, reason);
            }
        }

        private void ValidateTxs(Block block)
        {
            for (int i = 0; i < block.Transactions.Length; i++)
            {
                Transaction tx = block.Transactions[i];
                AddingTxEventArgs args = CheckTxPosdaoRules(new AddingTxEventArgs(i, tx, block, block.Transactions));
                if (args.Action != TxAction.Add)
                {
                    string reason = $"{tx.ToShortString()} doesn't have required permissions: {args.Reason}";
                    if (_logger.IsWarn) _logger.Warn($"Proposed block is not valid {block.ToString(Block.Format.FullHashAndNumber)}. {reason}.");
                    throw new InvalidBlockException(block, reason);
                }
            }
        }

        private void OnAddingTransaction(object? sender, AddingTxEventArgs e)
        {
            CheckTxPosdaoRules(e);
        }

        private AddingTxEventArgs CheckTxPosdaoRules(AddingTxEventArgs args)
        {
            AcceptTxResult? TryRecoverSenderAddress(Transaction tx, BlockHeader parentHeader, IReleaseSpec currentSpec)
            {
                if (tx.Signature is not null)
                {
                    EthereumEcdsa ecdsa = new(_specProvider.ChainId);
                    Address txSenderAddress = ecdsa.RecoverAddress(tx, !currentSpec.ValidateChainId);
                    if (tx.SenderAddress != txSenderAddress)
                    {
                        if (_logger.IsWarn) _logger.Warn($"Transaction {tx.ToShortString()} in block {args.Block.ToString(Block.Format.FullHashAndNumber)} had recovered sender address on validation.");
                        tx.SenderAddress = txSenderAddress;
                        return _txFilter.IsAllowed(tx, parentHeader, currentSpec);
                    }
                }

                return null;
            }

            IReleaseSpec spec = _specProvider.GetSpec(args.Block.Header);
            BlockHeader parentHeader = GetParentHeader(args.Block);
            AcceptTxResult isAllowed = _txFilter.IsAllowed(args.Transaction, parentHeader, spec);
            if (!isAllowed)
            {
                isAllowed = TryRecoverSenderAddress(args.Transaction, parentHeader, spec) ?? isAllowed;
            }

            if (!isAllowed)
            {
                args.Set(TxAction.Skip, isAllowed.ToString());
            }

            return args;
        }
    }

    public class NullAuRaValidator : IAuRaValidator
    {
        public Address[] Validators => [];
        public void OnBlockProcessingStart(Block block, ProcessingOptions options = ProcessingOptions.None) { }
        public void OnBlockProcessingEnd(Block block, TxReceipt[] receipts, ProcessingOptions options = ProcessingOptions.None) { }
    }
}
