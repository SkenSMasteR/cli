$ErrorActionPreference = 'Stop'
function Set-ProtectionRule($path, $rights, $inheritance, $action) {
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    $item = Get-Item -LiteralPath $path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'The update staging path and its parent must be regular directories'
    }
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, $rights, $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Deny)
    function Get-OwnRules($acl) {
        @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.IdentityReference -eq $sid -and $_.AccessControlType -eq 'Deny'
        })
    }
    function Test-BlockRule($candidate) {
        $candidate.FileSystemRights -eq $rights -and $candidate.InheritanceFlags -eq $inheritance -and $candidate.PropagationFlags -eq 'None'
    }
    $acl = [System.IO.Directory]::GetAccessControl($path, [System.Security.AccessControl.AccessControlSections]::Access)
    $ownRules = @(Get-OwnRules $acl)
    $blockRules = @($ownRules | Where-Object { Test-BlockRule $_ })
    if ($action -eq 'block' -and $blockRules.Count -eq 0) {
        if ($ownRules.Count -ne 0) { throw 'Existing user deny permissions must be managed separately' }
        $acl.AddAccessRule($rule)
        [System.IO.Directory]::SetAccessControl($path, $acl)
    } elseif ($action -eq 'unblock' -and $blockRules.Count -ne 0) {
        foreach ($entry in $blockRules) { $acl.RemoveAccessRuleSpecific($entry) }
        [System.IO.Directory]::SetAccessControl($path, $acl)
    }
    $remaining = @(Get-OwnRules ([System.IO.Directory]::GetAccessControl($path, [System.Security.AccessControl.AccessControlSections]::Access)) | Where-Object { Test-BlockRule $_ })
    return $remaining.Count -ne 0
}
try {
    $directory = $env:SPICETIFY_UPDATE_DIRECTORY
    $action = $env:SPICETIFY_UPDATE_ACTION
    if ($action -notin @('status', 'block', 'unblock')) { throw 'Unknown update action' }
    $parent = [System.IO.Path]::GetDirectoryName($directory)
    if ($action -eq 'block') {
        foreach ($path in @($parent, $directory)) {
            if (Test-Path -LiteralPath $path) {
                $item = Get-Item -LiteralPath $path -Force
                if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                    throw 'The update staging path and its parent must be regular directories'
                }
            }
        }
        [void][System.IO.Directory]::CreateDirectory($directory)
    }
    # DELETE on a child can be bypassed by DELETE_CHILD on its parent.
    # This non-inherited parent rule closes that route without denying
    # writes or deletion of other files that grant their own DELETE access.
    $parentBlocked = Set-ProtectionRule $parent ([System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) ([System.Security.AccessControl.InheritanceFlags]::None) $action
    $rights = [System.Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ExecuteFile'
    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $directoryBlocked = Set-ProtectionRule $directory $rights $inheritance $action
    if ($parentBlocked -and $directoryBlocked) { Write-Output 'blocked' }
    elseif ($parentBlocked -or $directoryBlocked) { Write-Output 'partial' }
    else { Write-Output 'allowed' }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
