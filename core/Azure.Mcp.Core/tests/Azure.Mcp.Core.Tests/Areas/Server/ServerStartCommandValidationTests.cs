// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Http;
using Microsoft.Mcp.Core.Areas.Server.Commands;
using Microsoft.Mcp.Core.Areas.Server.Options;
using Microsoft.Mcp.Core.Commands;
using Xunit;

namespace Azure.Mcp.Core.Tests.Areas.Server;

/// <summary>
/// Unit tests for <see cref="ServerStartCommand"/> outgoing-authentication option handling.
///
/// These lock in the hardened remote-host auth model (issue #2975) without starting a server:
/// - On-Behalf-Of (OBO) is only valid in authenticated HTTP mode.
/// - The default (<see cref="OutgoingAuthStrategy.NotSet"/>) strategy resolves cleanly onto the
///   three supported deployments: OBO, hosting-environment identity, and the no-incoming-auth dev path.
/// </summary>
public sealed class ServerStartCommandValidationTests
{
    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("/mcp", "/mcp")]
    [InlineData("/mcp/", "/mcp")]
    public void GetHttpBasePath_NormalizesConfiguredPath(string? configuredPath, string expectedPath)
    {
        Assert.Equal(expectedPath, ServerStartCommand.NormalizeHttpBasePath(configuredPath));
    }

    [Theory]
    [InlineData("mcp")]
    [InlineData("/mcp?query")]
    [InlineData("/mcp#fragment")]
    [InlineData("/mcp\\nested")]
    public void GetHttpBasePath_RejectsInvalidPath(string configuredPath)
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ServerStartCommand.NormalizeHttpBasePath(configuredPath));
        Assert.Contains(ServerStartCommand.HttpBasePathEnvironmentVariable, exception.Message);
    }

    [Fact]
    public void BuildMcpScope_UsesTheAdvertisedResourceUri()
    {
        Assert.Equal(
            "https://azuremcp.grdc.com.au/mcp/Mcp.Tools.ReadWrite",
            ServerStartCommand.BuildMcpScope("https://azuremcp.grdc.com.au/mcp"));
    }

    [Fact]
    public void BuildHttpUrl_RemovesDefaultHttpsPortAndPreservesBasePath()
    {
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("azuremcp.grdc.com.au", 443);
        context.Request.PathBase = new PathString("/mcp");

        Assert.Equal(
            "https://azuremcp.grdc.com.au/mcp",
            ServerStartCommand.BuildHttpUrl(context.Request, "https", string.Empty));
    }

    [Fact]
    public void BuildHttpUrl_UsesConfiguredBasePathWhenMetadataRequestHasNoPath()
    {
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("azuremcp.grdc.com.au", 443);

        Assert.Equal(
            "https://azuremcp.grdc.com.au/mcp",
            ServerStartCommand.BuildHttpUrl(context.Request, "https", string.Empty, "/mcp"));
    }

    [Fact]
    public void GetProtectedResourceMetadataPath_InsertsWellKnownBeforeConfiguredBasePath()
    {
        Assert.Equal(
            "/.well-known/oauth-protected-resource/mcp",
            ServerStartCommand.GetProtectedResourceMetadataPath("/mcp/"));
    }

    [Fact]
    public void BuildHttpUrl_CreatesRfc9728PathInsertionChallengeUrl()
    {
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("azuremcp.grdc.com.au", 443);

        string metadataPath = ServerStartCommand.GetProtectedResourceMetadataPath("/mcp");

        Assert.Equal(
            "https://azuremcp.grdc.com.au/.well-known/oauth-protected-resource/mcp",
            ServerStartCommand.BuildHttpUrl(context.Request, "https", metadataPath, string.Empty));
    }

    [Theory]
    [InlineData("/.well-known/oauth-protected-resource", true)]
    [InlineData("/.well-known/oauth-protected-resource/mcp", true)]
    [InlineData("/mcp/.well-known/oauth-protected-resource", true)]
    [InlineData("/.well-known/oauth-protected-resource/other", false)]
    [InlineData("/.well-known/oauth-authorization-server/mcp", false)]
    public void IsProtectedResourceMetadataRequest_RecognizesSupportedDiscoveryPaths(
        string requestPath,
        bool expected)
    {
        Assert.Equal(
            expected,
            ServerStartCommand.IsProtectedResourceMetadataRequest(requestPath, "/mcp"));
    }

    private static ValidationResult Validate(ServerStartOptions options)
    {
        var command = new ServerStartCommand();
        var validationResult = new ValidationResult();
        command.ValidateOptions(options, validationResult);
        return validationResult;
    }

    [Fact]
    public void ValidateOptions_OnBehalfOf_WithStdioTransport_AddsError()
    {
        // OBO exchanges an inbound user token, which only exists in authenticated HTTP mode.
        var options = new ServerStartOptions
        {
            Transport = TransportTypes.StdIo,
            OutgoingAuthStrategy = OutgoingAuthStrategy.UseOnBehalfOf
        };

        var result = Validate(options);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("authenticated HTTP mode"));
    }

    [Fact]
    public void ValidateOptions_OnBehalfOf_WithIncomingAuthDisabled_AddsError()
    {
        // Disabling incoming auth removes the inbound identity OBO needs to exchange.
        var options = new ServerStartOptions
        {
            Transport = TransportTypes.Http,
            DangerouslyDisableHttpIncomingAuth = true,
            OutgoingAuthStrategy = OutgoingAuthStrategy.UseOnBehalfOf
        };

        var result = Validate(options);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("authenticated HTTP mode"));
    }

    [Fact]
    public void ValidateOptions_OnBehalfOf_WithAuthenticatedHttp_IsValid()
    {
        var options = new ServerStartOptions
        {
            Transport = TransportTypes.Http,
            DangerouslyDisableHttpIncomingAuth = false,
            OutgoingAuthStrategy = OutgoingAuthStrategy.UseOnBehalfOf
        };

        var result = Validate(options);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void ValidateOptions_HostingEnvironmentIdentity_WithStdio_IsValid()
    {
        // Hosting-environment identity is valid for every transport, including stdio.
        var options = new ServerStartOptions
        {
            Transport = TransportTypes.StdIo,
            OutgoingAuthStrategy = OutgoingAuthStrategy.UseHostingEnvironmentIdentity
        };

        var result = Validate(options);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void PostBindOptions_NotSet_AuthenticatedHttp_ResolvesToOnBehalfOf()
    {
        var command = new ServerStartCommand();
        var options = new ServerStartOptions
        {
            Transport = TransportTypes.Http,
            DangerouslyDisableHttpIncomingAuth = false,
            OutgoingAuthStrategy = OutgoingAuthStrategy.NotSet
        };

        command.PostBindOptions(options);

        Assert.Equal(OutgoingAuthStrategy.UseOnBehalfOf, options.OutgoingAuthStrategy);
    }

    [Fact]
    public void PostBindOptions_NotSet_HttpWithIncomingAuthDisabled_ResolvesToHostingEnvironmentIdentity()
    {
        var command = new ServerStartCommand();
        var options = new ServerStartOptions
        {
            Transport = TransportTypes.Http,
            DangerouslyDisableHttpIncomingAuth = true,
            OutgoingAuthStrategy = OutgoingAuthStrategy.NotSet
        };

        command.PostBindOptions(options);

        Assert.Equal(OutgoingAuthStrategy.UseHostingEnvironmentIdentity, options.OutgoingAuthStrategy);
    }

    [Fact]
    public void PostBindOptions_NotSet_StdioTransport_ResolvesToHostingEnvironmentIdentity()
    {
        var command = new ServerStartCommand();
        var options = new ServerStartOptions
        {
            Transport = TransportTypes.StdIo,
            OutgoingAuthStrategy = OutgoingAuthStrategy.NotSet
        };

        command.PostBindOptions(options);

        Assert.Equal(OutgoingAuthStrategy.UseHostingEnvironmentIdentity, options.OutgoingAuthStrategy);
    }
}
