# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Test-PostureAppOnlySignIn {
    <#
    .SYNOPSIS
        Whether a Graph session is an application's own (the scheduled run's managed identity, an app with a
        certificate) and not a person's.
    .DESCRIPTION
        The Graph SDK names the kind of sign-in in AuthType. A person who signs in through the TenantKeep app is
        reported as UserProvidedAccessToken, since the module hands the SDK the token; a person who ran
        Connect-MgGraph is Delegated. Both are a person, and what they lack is fixed by the tenant approving the
        app again. An application's own sign-in is fixed by granting the identity a role. Seen live 2026-11-23:
        a local run was told to grant the identity a permission, because everything but Delegated was read as an
        application.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] [AllowEmptyString()] [string] $AuthType)

    return ([string]$AuthType -in 'AppOnly', 'ManagedIdentity', 'EnvironmentVariable')
}
