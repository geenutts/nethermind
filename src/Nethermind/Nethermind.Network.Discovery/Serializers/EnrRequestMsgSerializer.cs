// SPDX-FileCopyrightText: 2022 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using Autofac.Features.AttributeFilters;
using DotNetty.Buffers;
using Nethermind.Core.Crypto;
using Nethermind.Crypto;
using Nethermind.Network.Discovery.Messages;
using Nethermind.Serialization.Rlp;

namespace Nethermind.Network.Discovery.Serializers;

public class EnrRequestMsgSerializer : DiscoveryMsgSerializerBase, IZeroInnerMessageSerializer<EnrRequestMsg>
{
    public EnrRequestMsgSerializer(IEcdsa ecdsa, [KeyFilter(IProtectedPrivateKey.NodeKey)] IPrivateKeyGenerator nodeKey, INodeIdResolver nodeIdResolver)
        : base(ecdsa, nodeKey, nodeIdResolver) { }

    public void Serialize(IByteBuffer byteBuffer, EnrRequestMsg msg)
    {
        int length = GetLength(msg, out int contentLength);

        byteBuffer.MarkIndex();
        PrepareBufferForSerialization(byteBuffer, length, (byte)msg.MsgType);
        NettyRlpStream stream = new(byteBuffer);
        stream.StartSequence(contentLength);
        stream.Encode(msg.ExpirationTime);

        byteBuffer.ResetIndex();

        AddSignatureAndMdc(byteBuffer, length + 1);
    }

    public EnrRequestMsg Deserialize(IByteBuffer msgBytes)
    {
        (PublicKey farPublicKey, Memory<byte> mdc, IByteBuffer data) = PrepareForDeserialization(msgBytes);
        NettyRlpStream rlpStream = new(data);

        rlpStream.ReadSequenceLength();
        long expirationTime = rlpStream.DecodeLong();

        EnrRequestMsg msg = new(farPublicKey, mdc, expirationTime);
        return msg;
    }

    public int GetLength(EnrRequestMsg message, out int contentLength)
    {
        contentLength = Rlp.LengthOf(message.ExpirationTime);
        return Rlp.LengthOfSequence(contentLength);
    }
}
