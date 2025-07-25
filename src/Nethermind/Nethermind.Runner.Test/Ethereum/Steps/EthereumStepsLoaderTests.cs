// SPDX-FileCopyrightText: 2025 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Autofac;
using FluentAssertions;
using Nethermind.Api.Extensions;
using Nethermind.Api.Steps;
using Nethermind.Consensus.AuRa;
using Nethermind.Consensus.AuRa.Config;
using Nethermind.Core;
using Nethermind.Core.Collections;
using Nethermind.Grpc;
using Nethermind.Init;
using Nethermind.Init.Snapshot;
using Nethermind.Init.Steps;
using Nethermind.Merge.AuRa;
using Nethermind.Merge.Plugin;
using Nethermind.Optimism;
using Nethermind.Runner.Ethereum;
using Nethermind.Runner.Ethereum.Modules;
using Nethermind.Shutter;
using Nethermind.Shutter.Config;
using Nethermind.Specs.ChainSpecStyle;
using Nethermind.Specs.Test.ChainSpecStyle;
using Nethermind.Taiko;
using NUnit.Framework;

namespace Nethermind.Runner.Test.Ethereum.Steps;

public class EthereumStepsLoaderTests
{
    [Test]
    public void BuildInSteps_IsCorrect()
    {
        var steps = new HashSet<StepInfo>();
        steps.AddRange(LoadStepInfoFromAssembly(typeof(InitializeBlockTree).Assembly));
        steps.AddRange(LoadStepInfoFromAssembly(typeof(EthereumRunner).Assembly));

        HashSet<Type> optionalSteps = [typeof(RunVerifyTrie), typeof(ExitOnInvalidBlock)];
        steps = steps.Where((s) => !optionalSteps.Contains(s.StepBaseType)).ToHashSet();

        using IContainer container = new ContainerBuilder()
            .AddModule(new BuiltInStepsModule())
            .AddModule(new StartRpcStepsModule(new GrpcConfig()
            {
                Enabled = true
            }))
            .Build();

        container.Resolve<IEnumerable<StepInfo>>().ToHashSet().Should().BeEquivalentTo(steps);
    }

    [Test]
    public void DoubleCheck_PluginsSteps()
    {
        CheckPlugin(new AuRaPlugin(new ChainSpec() { EngineChainSpecParametersProvider = new TestChainSpecParametersProvider(new AuRaChainSpecEngineParameters()) }));
        CheckPlugin(new OptimismPlugin(new ChainSpec() { EngineChainSpecParametersProvider = new TestChainSpecParametersProvider(new OptimismChainSpecEngineParameters()) }));
        CheckPlugin(new TaikoPlugin(new ChainSpec()));
        CheckPlugin(new AuRaMergePlugin(new ChainSpec(), new MergeConfig()));
        CheckPlugin(new SnapshotPlugin(new SnapshotConfig()));
        CheckPlugin(new ShutterPlugin(new ShutterConfig(), new MergeConfig(), new ChainSpec()));
    }

    [Test]
    public void LoadStepsFromHere()
    {
        LoadStepInfoFromAssembly(GetType().Assembly)
            .ToArray()
            .Should()
            .BeEquivalentTo([
                new StepInfo(typeof(StepLong)),
                new StepInfo(typeof(StepWithLogManagerInConstructor)),
                new StepInfo(typeof(StepWithSameBaseStep)),
                new StepInfo(typeof(StepForever)),
                new StepInfo(typeof(StepA)),
                new StepInfo(typeof(StepB)),
                new StepInfo(typeof(StepCAuRa)),
                new StepInfo(typeof(StepCStandard)),
                new StepInfo(typeof(StepE)),
                new StepInfo(typeof(FailedConstructorWithInvalidConfigurationStep)),
            ]);
    }

    private void CheckPlugin(INethermindPlugin plugin)
    {
        using IContainer container = new ContainerBuilder()
            .AddModule(plugin.Module)
            .Build();

        StepInfo[] steps = container.Resolve<IList<StepInfo>>().ToArray();
        steps.ToHashSet().Should().BeEquivalentTo(LoadStepInfoFromAssembly(plugin.GetType().Assembly));
    }

    private static IEnumerable<StepInfo> LoadStepInfoFromAssembly(Assembly assembly)
    {
        IEnumerable<Type> stepTypes = assembly.GetExportedTypes()
            .Where(t => !t.IsInterface && !t.IsAbstract && StepInfo.IsStepType(t));

        foreach (Type stepType in stepTypes)
        {
            yield return new StepInfo(stepType);
        }
    }

}
