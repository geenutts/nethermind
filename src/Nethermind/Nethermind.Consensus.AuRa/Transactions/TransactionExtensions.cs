// SPDX-FileCopyrightText: 2022 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using Nethermind.Core;
using Nethermind.Core.Specs;

namespace Nethermind.Consensus.AuRa.Transactions
{
    public static class TransactionExtensions
    {
        public static bool IsZeroGasPrice(this Transaction tx, IReleaseSpec releaseSpec)
        {
            bool isEip1559Enabled = releaseSpec.IsEip1559Enabled;
            bool checkByFeeCap = isEip1559Enabled && tx.Supports1559;
            if (checkByFeeCap && !tx.MaxFeePerGas.IsZero) // only 0 gas price transactions are system transactions and can be whitelisted
            {
                return false;
            }
            else if (!tx.GasPrice.IsZero && !checkByFeeCap)
            {
                return false;
            }

            return true;
        }
    }
}
