// SPDX-FileCopyrightText: 2022 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using System.Collections;
using Nethermind.Core.Collections;
using Nethermind.Core.Crypto;
using Nethermind.Logging;
using Nethermind.Network.Config;
using Nethermind.Stats.Model;
using static Nethermind.Network.Discovery.RoutingTable.NodeBucket;

namespace Nethermind.Network.Discovery.RoutingTable;

public class NodeTable : INodeTable
{
    private readonly ILogger _logger;
    private readonly INetworkConfig _networkConfig;
    private readonly IDiscoveryConfig _discoveryConfig;
    private readonly INodeDistanceCalculator _nodeDistanceCalculator;

    public NodeTable(
        INodeDistanceCalculator? nodeDistanceCalculator,
        IDiscoveryConfig? discoveryConfig,
        INetworkConfig? networkConfig,
        ILogManager? logManager)
    {
        _logger = logManager?.GetClassLogger() ?? throw new ArgumentNullException(nameof(logManager));
        _networkConfig = networkConfig ?? throw new ArgumentNullException(nameof(networkConfig));
        _discoveryConfig = discoveryConfig ?? throw new ArgumentNullException(nameof(discoveryConfig));
        _nodeDistanceCalculator = nodeDistanceCalculator ?? throw new ArgumentNullException(nameof(nodeDistanceCalculator));

        Buckets = new NodeBucket[_discoveryConfig.BucketsCount];
        for (int i = 0; i < Buckets.Length; i++)
        {
            Buckets[i] = new NodeBucket(i, _discoveryConfig.BucketSize, _discoveryConfig.DropFullBucketNodeProbability);
        }
    }

    public Node? MasterNode { get; private set; }

    public NodeBucket[] Buckets { get; }

    public NodeAddResult AddNode(Node node)
    {
        CheckInitialization();

        if (_logger.IsTrace) _logger.Trace($"Adding node to NodeTable: {node}");
        int distanceFromMaster = _nodeDistanceCalculator.CalculateDistance(MasterNode!.IdHash, node.IdHash);
        NodeBucket bucket = Buckets[distanceFromMaster > 0 ? distanceFromMaster - 1 : 0];
        return bucket.AddNode(node);
    }

    public void ReplaceNode(Node nodeToRemove, Node nodeToAdd)
    {
        CheckInitialization();

        int distanceFromMaster = _nodeDistanceCalculator.CalculateDistance(MasterNode!.IdHash, nodeToAdd.IdHash);
        NodeBucket bucket = Buckets[distanceFromMaster > 0 ? distanceFromMaster - 1 : 0];
        bucket.ReplaceNode(nodeToRemove, nodeToAdd);
    }

    private void CheckInitialization()
    {
        if (MasterNode is null)
        {
            throw new InvalidOperationException("Master not has not been initialized");
        }
    }

    public void RefreshNode(Node node)
    {
        CheckInitialization();

        int distanceFromMaster = _nodeDistanceCalculator.CalculateDistance(MasterNode!.IdHash, node.IdHash);
        NodeBucket bucket = Buckets[distanceFromMaster > 0 ? distanceFromMaster - 1 : 0];
        bucket.RefreshNode(node);
    }

    public ClosestNodesEnumerator GetClosestNodes()
    {
        return new ClosestNodesEnumerator(Buckets, _discoveryConfig.BucketSize);
    }

    public struct ClosestNodesEnumerator : IEnumerator<Node>, IEnumerable<Node>
    {
        private readonly NodeBucket[] _buckets;
        private readonly int _bucketSize;
        private BondedItemsEnumerator _itemEnumerator;
        private bool _enumeratorSet;
        private int _bucketIndex;
        private int _count;

        public ClosestNodesEnumerator(NodeBucket[] buckets, int bucketSize)
        {
            _buckets = buckets;
            _bucketSize = bucketSize;
            Current = null!;
            _bucketIndex = -1;
            _count = 0;
        }

        public Node Current { get; private set; }

        readonly object IEnumerator.Current => Current;

        public bool MoveNext()
        {
            while (_count < _bucketSize)
            {
                if (!_enumeratorSet || !_itemEnumerator.MoveNext())
                {
                    _itemEnumerator.Dispose();
                    _bucketIndex++;
                    if (_bucketIndex >= _buckets.Length)
                    {
                        return false;
                    }

                    _itemEnumerator = _buckets[_bucketIndex].BondedItems.GetEnumerator();
                    _enumeratorSet = true;
                    continue;
                }

                Current = _itemEnumerator.Current.Node!;
                _count++;
                return true;
            }

            return false;
        }

        void IEnumerator.Reset() => throw new NotSupportedException();

        public readonly void Dispose() => _itemEnumerator.Dispose();

        public readonly ClosestNodesEnumerator GetEnumerator() => this;

        readonly IEnumerator<Node> IEnumerable<Node>.GetEnumerator() => this;

        readonly IEnumerator IEnumerable.GetEnumerator() => this;
    }

    public ClosestNodesFromNodeEnumerator GetClosestNodes(byte[] nodeId)
    {
        return GetClosestNodes(nodeId, _discoveryConfig.BucketSize);
    }

    public ClosestNodesFromNodeEnumerator GetClosestNodes(byte[] nodeId, int bucketSize)
    {
        CheckInitialization();
        return new ClosestNodesFromNodeEnumerator(Buckets, nodeId, _nodeDistanceCalculator, Math.Min(bucketSize, _discoveryConfig.BucketSize));
    }

    public struct ClosestNodesFromNodeEnumerator : IEnumerator<Node>, IEnumerable<Node>
    {
        private readonly ArrayPoolList<Node> _sortedNodes;
        private int _currentIndex;

        public ClosestNodesFromNodeEnumerator(NodeBucket[] buckets, byte[] targetNodeId, INodeDistanceCalculator calculator, int bucketSize)
        {
            _sortedNodes = new ArrayPoolList<Node>(capacity: bucketSize);
            Hash256 idHash = Keccak.Compute(targetNodeId);
            foreach (NodeBucket bucket in buckets)
            {
                foreach (NodeBucketItem item in bucket.BondedItems)
                {
                    Node? node = item.Node;
                    if (node is not null && node.IdHash != idHash)
                    {
                        _sortedNodes.Add(node);
                    }
                }
            }

            _sortedNodes.Sort((Node a, Node b) =>
            {
                const int Closer = int.MinValue;
                const int Further = int.MaxValue;

                if (Nullable.Equals(a.ValidatedProtocol, b.ValidatedProtocol))
                {
                    return calculator.CalculateDistance(a.Id.Hash, idHash).CompareTo(calculator.CalculateDistance(b.Id.Hash, idHash));
                }
                else if (a.ValidatedProtocol.HasValue)
                {
                    // Prefer nodes validated on same protocol, network and fork
                    return a.ValidatedProtocol == true ? Closer : Further;
                }
                else
                {
                    // b must have value; swap high and low from a
                    return b.ValidatedProtocol == true ? Further : Closer;
                }
            });

            if (_sortedNodes.Count > bucketSize)
            {
                _sortedNodes.ReduceCount(bucketSize);
            }

            _currentIndex = -1;
        }

        public readonly int Count => _sortedNodes.Count;

        public readonly Node Current => _sortedNodes[_currentIndex];

        readonly object IEnumerator.Current => Current;

        public bool MoveNext()
        {
            if (_currentIndex + 1 < _sortedNodes.Count)
            {
                _currentIndex++;
                return true;
            }
            return false;
        }

        void IEnumerator.Reset() => throw new NotSupportedException();
        public readonly void Dispose()
        {
            _sortedNodes.Dispose();
        }

        public readonly ClosestNodesFromNodeEnumerator GetEnumerator() => this;
        readonly IEnumerator<Node> IEnumerable<Node>.GetEnumerator() => this;

        readonly IEnumerator IEnumerable.GetEnumerator() => this;
    }

    public void Initialize(PublicKey masterNodeKey)
    {
        MasterNode = new Node(masterNodeKey, _networkConfig.ExternalIp, _networkConfig.DiscoveryPort);
        if (_logger.IsTrace) _logger.Trace($"Created MasterNode: {MasterNode}");
    }
}
