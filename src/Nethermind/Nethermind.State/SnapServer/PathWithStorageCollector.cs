// SPDX-FileCopyrightText: 2024 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using Nethermind.Core.Buffers;
using Nethermind.Core.Collections;
using Nethermind.Core.Crypto;
using Nethermind.State.Snap;
using Nethermind.Trie;

namespace Nethermind.State.SnapServer;

public class PathWithStorageCollector : RangeQueryVisitor.ILeafValueCollector
{
    public ArrayPoolList<PathWithStorageSlot> Slots { get; } = new(0);

    public int Collect(in ValueHash256 path, SpanSource value)
    {
        Slots.Add(new PathWithStorageSlot(in path, value.ToArray()));
        return 32 + value.Length;
    }
}
