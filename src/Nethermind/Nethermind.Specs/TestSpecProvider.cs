// SPDX-FileCopyrightText: 2022 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using Nethermind.Core;
using Nethermind.Core.Specs;
using Nethermind.Int256;

namespace Nethermind.Specs
{
    public class TestSpecProvider : ISpecProvider
    {
        private ForkActivation? _theMergeBlock = null;

        public TestSpecProvider(IReleaseSpec initialSpecToReturn)
        {
            SpecToReturn = initialSpecToReturn;
            GenesisSpec = initialSpecToReturn;
        }

        public void UpdateMergeTransitionInfo(long? blockNumber, UInt256? terminalTotalDifficulty = null)
        {
            if (blockNumber is not null)
                _theMergeBlock = (ForkActivation)blockNumber;
            if (terminalTotalDifficulty is not null)
                TerminalTotalDifficulty = terminalTotalDifficulty;
        }

        public ForkActivation? MergeBlockNumber => _theMergeBlock;
        public ulong TimestampFork { get; set; } = ISpecProvider.TimestampForkNever;
        public UInt256? TerminalTotalDifficulty { get; set; }

        public IReleaseSpec GenesisSpec { get; set; }

        IReleaseSpec ISpecProvider.GetSpecInternal(ForkActivation forkActivation) => forkActivation.BlockNumber == 0 || forkActivation.BlockNumber < ForkOnBlockNumber ? GenesisSpec : SpecToReturn;
        public IReleaseSpec SpecToReturn { get; set; }

        public long? DaoBlockNumber { get; set; }
        public ulong? BeaconChainGenesisTimestamp { get; set; }
        public ulong? _networkId;
        public ulong NetworkId { get { return _networkId ?? TestBlockchainIds.NetworkId; } set { _networkId = value; } }

        public ulong? _chainId;
        public ulong ChainId { get { return _chainId ?? TestBlockchainIds.ChainId; } set { _chainId = value; } }

        public ForkActivation[] TransitionActivations { get; set; } = new ForkActivation[] { (ForkActivation)0 };
        public bool AllowTestChainOverride { get; set; } = true;

        public long? ForkOnBlockNumber { get; set; }

        private TestSpecProvider() { }

        public static readonly TestSpecProvider Instance = new();
    }
}
