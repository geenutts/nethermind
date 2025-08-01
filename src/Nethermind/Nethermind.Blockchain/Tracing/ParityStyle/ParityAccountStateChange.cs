// SPDX-FileCopyrightText: 2022 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using System.Collections.Generic;

using Nethermind.Int256;
using System.Text.Json.Serialization;

namespace Nethermind.Blockchain.Tracing.ParityStyle;

[JsonConverter(typeof(ParityAccountStateChangeJsonConverter))]
public class ParityAccountStateChange
{
    public ParityStateChange<byte[]>? Code { get; set; }
    public ParityStateChange<UInt256?>? Balance { get; set; }
    public ParityStateChange<UInt256?>? Nonce { get; set; }
    public Dictionary<UInt256, ParityStateChange<byte[]>>? Storage { get; set; }
}
