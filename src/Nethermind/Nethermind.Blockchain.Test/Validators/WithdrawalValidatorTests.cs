// SPDX-FileCopyrightText: 2022 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using Nethermind.Consensus.Validators;
using Nethermind.Core;
using Nethermind.Core.Crypto;
using Nethermind.Core.Specs;
using Nethermind.Core.Test.Builders;
using Nethermind.Logging;
using Nethermind.Serialization.Rlp;
using Nethermind.Specs.Forks;
using Nethermind.Specs.Test;
using Nethermind.State.Proofs;
using NUnit.Framework;

namespace Nethermind.Blockchain.Test.Validators;

public class WithdrawalValidatorTests
{
    [Test, MaxTime(Timeout.MaxTestTime)]
    public void Not_null_withdrawals_are_invalid_pre_shanghai()
    {
        ISpecProvider specProvider = new CustomSpecProvider(((ForkActivation)0, London.Instance));
        BlockValidator blockValidator = new(Always.Valid, Always.Valid, Always.Valid, specProvider, LimboLogs.Instance);
        bool isValid = blockValidator.ValidateSuggestedBlock(Build.A.Block.WithWithdrawals([TestItem.WithdrawalA_1Eth, TestItem.WithdrawalB_2Eth]).TestObject);
        Assert.That(isValid, Is.False);
    }

    [Test, MaxTime(Timeout.MaxTestTime)]
    public void Null_withdrawals_are_invalid_post_shanghai()
    {
        ISpecProvider specProvider = new CustomSpecProvider(((ForkActivation)0, Shanghai.Instance));
        BlockValidator blockValidator = new(Always.Valid, Always.Valid, Always.Valid, specProvider, LimboLogs.Instance);
        bool isValid = blockValidator.ValidateSuggestedBlock(Build.A.Block.TestObject);
        Assert.That(isValid, Is.False);
    }

    [Test, MaxTime(Timeout.MaxTestTime)]
    public void Withdrawals_with_incorrect_withdrawals_root_are_invalid()
    {
        ISpecProvider specProvider = new CustomSpecProvider(((ForkActivation)0, Shanghai.Instance));
        BlockValidator blockValidator = new(Always.Valid, Always.Valid, Always.Valid, specProvider, LimboLogs.Instance);
        Withdrawal[] withdrawals = [TestItem.WithdrawalA_1Eth, TestItem.WithdrawalB_2Eth];
        bool isValid = blockValidator.ValidateSuggestedBlock(Build.A.Block.WithWithdrawals(withdrawals).WithWithdrawalsRoot(TestItem.KeccakD).TestObject);
        Assert.That(isValid, Is.False);
    }

    [Test, MaxTime(Timeout.MaxTestTime)]
    public void Empty_withdrawals_are_valid_post_shanghai()
    {
        ISpecProvider specProvider = new CustomSpecProvider(((ForkActivation)0, Shanghai.Instance));
        BlockValidator blockValidator = new(Always.Valid, Always.Valid, Always.Valid, specProvider, LimboLogs.Instance);
        Withdrawal[] withdrawals = [];
        Hash256 withdrawalRoot = new WithdrawalTrie(withdrawals).RootHash;
        bool isValid = blockValidator.ValidateSuggestedBlock(Build.A.Block.WithWithdrawals(withdrawals).WithWithdrawalsRoot(withdrawalRoot).TestObject);
        Assert.That(isValid, Is.True);
    }

    [Test, MaxTime(Timeout.MaxTestTime)]
    public void Correct_withdrawals_block_post_shanghai()
    {
        ISpecProvider specProvider = new CustomSpecProvider(((ForkActivation)0, Shanghai.Instance));
        BlockValidator blockValidator = new(Always.Valid, Always.Valid, Always.Valid, specProvider, LimboLogs.Instance);
        Withdrawal[] withdrawals = [TestItem.WithdrawalA_1Eth, TestItem.WithdrawalB_2Eth];
        Hash256 withdrawalRoot = new WithdrawalTrie(withdrawals).RootHash;
        bool isValid = blockValidator.ValidateSuggestedBlock(Build.A.Block.WithWithdrawals(withdrawals).WithWithdrawalsRoot(withdrawalRoot).TestObject);
        Assert.That(isValid, Is.True);
    }
}
