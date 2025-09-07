[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\ListScheduledTasks-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log',
  [int]   $MaxTasks = 0
)

$ErrorActionPreference = 'Stop'
$HostName  = $env:COMPUTERNAME
$LogMaxKB  = 100
$LogKeep   = 5
$runStart  = Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN' {Write-Host $line -ForegroundColor Yellow}
    'DEBUG'{if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')){Write-Verbose $line}}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath."+($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function To-ISO8601 {
  param($dt)
  if($dt -and $dt -is [datetime] -and $dt.Year -gt 1900){ $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
}

function New-NdjsonLine {
  param([hashtable]$Data)
  if (-not $Data.ContainsKey('timestamp'))      { $Data['timestamp'] = (Get-Date).ToUniversalTime().ToString('o') }
  if (-not $Data.ContainsKey('host'))           { $Data['host'] = $HostName }
  if (-not $Data.ContainsKey('action'))         { $Data['action'] = 'list_scheduled_tasks' }
  if (-not $Data.ContainsKey('copilot_action')) { $Data['copilot_action'] = $true }
  return ($Data | ConvertTo-Json -Compress -Depth 7)
}

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force }
  catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

function Ensure-TaskSchedulerOperationalLog {
  try{
    $gl = wevtutil gl Microsoft-Windows-TaskScheduler/Operational 2>$null
    if($gl -notmatch 'enabled:\s*true'){
      Write-Log "Enabling Task Scheduler Operational log" 'INFO'
      wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true | Out-Null
    }
  }catch{
    Write-Log "Could not query/enable Operational log: $($_.Exception.Message)" 'WARN'
  }
}

Rotate-Log
Write-Log "=== SCRIPT START : List Scheduled Tasks (host=$HostName) ==="

try{
  Ensure-TaskSchedulerOperationalLog
  Write-Log "Loading tasks..." 'INFO'
  $tasks = @()
  try { $tasks = Get-ScheduledTask -ErrorAction Stop }
  catch { Write-Log ("Get-ScheduledTask error: {0}" -f $_.Exception.Message) 'WARN' }

  if($MaxTasks -gt 0 -and $tasks.Count -gt $MaxTasks){
    Write-Log ("Capping tasks from {0} to {1}" -f $tasks.Count, $MaxTasks) 'WARN'
    $tasks = $tasks | Select-Object -First $MaxTasks
  }

  $events = @()
  try{
    $filter = @{
      LogName   = 'Microsoft-Windows-TaskScheduler/Operational'
      Id        = @(200,201,203)
      StartTime = (Get-Date).AddDays(-7)
    }
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
  }catch{
    Write-Log "Get-WinEvent failed: $($_.Exception.Message)" 'WARN'
  }

  $tsNow = (Get-Date).ToString('o')
  $lines = New-Object System.Collections.ArrayList

  [void]$lines.Add( (New-NdjsonLine @{
    item           = 'config'
    note           = 'operational log: IDs 200/201/203 last 7 days; up to 5 recent events per task'
  }) )

  [void]$lines.Add( (New-NdjsonLine @{
    item          = 'verify_source'
    sources       = @('Get-ScheduledTask','Get-ScheduledTaskInfo','TaskScheduler/Operational (wevtutil)')
    events_filter = @{ LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=@(200,201,203); StartTime=(Get-Date).AddDays(-7) }
  }) )

  [void]$lines.Add( (New-NdjsonLine @{
    item           = 'summary'
    task_count     = ($tasks | Measure-Object).Count
    events_loaded  = ($events | Measure-Object).Count
  }) )

  foreach($task in $tasks){
    $info = $null
    try { $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop } catch {}

    $stateVal = if($info -and $info.State){ $info.State } elseif($task.State){ $task.State } else { 'Unknown' }

    $author   = $null
    $runLevel = $null
    try { $author = $task.Author }   catch {}
    try { $runLevel = $task.Principal.RunLevel } catch {}

    $triggerStrs = @()
    if ($task.Triggers) {
      foreach ($t in $task.Triggers) {
        $desc = $t.TriggerType
        if ($t.PSObject.Properties.Name -contains 'StartBoundary' -and $t.StartBoundary) {
          try { $desc += '@' + (Get-Date $t.StartBoundary).ToString('yyyy-MM-dd HH:mm') } catch {}
        }
        if ($t.ToString() -match 'Logon')  { $desc += ' (Logon)' }
        if ($t.ToString() -match 'Boot')   { $desc += ' (Boot)'  }
        if ($t.ToString() -match 'Daily')  { $desc += ' (Daily)' }
        if ($t.ToString() -match 'Weekly') { $desc += ' (Weekly)'}
        if ($t.ToString() -match 'Monthly'){ $desc += ' (Monthly)'}
        $triggerStrs += $desc
      }
    }

    $actionStrs = @()
    if ($task.Actions) {
      foreach ($a in $task.Actions) {
        if ($a -and $a.Execute) {
          if ($a.Arguments) { $actionStrs += ('{0} {1}' -f $a.Execute, $a.Arguments) }
          else { $actionStrs += $a.Execute }
        }
      }
    }

    $fullName = ($task.TaskPath + $task.TaskName)

    [void]$lines.Add( (New-NdjsonLine @{
      item             = 'task'
      task_name        = $task.TaskName
      full_name        = $fullName
      path             = $task.TaskPath
      state            = $stateVal
      last_run_time    = (To-ISO8601 ($info.LastRunTime))
      next_run_time    = (To-ISO8601 ($info.NextRunTime))
      last_task_result = $info.LastTaskResult
      author           = $author
      run_level        = $runLevel
      triggers         = ($triggerStrs -join '; ')
      actions          = ($actionStrs  -join '; ')
    }) )

    try{
      $taskEvents = $events | Where-Object {
        $_.Properties.Count -ge 2 -and $_.Properties[0].Value -eq $fullName
      } | Sort-Object TimeCreated -Descending | Select-Object -First 5

      foreach($ev in $taskEvents){
        $result = $null
        try { $result = $ev.Properties[1].Value } catch {}
        [void]$lines.Add( (New-NdjsonLine @{
          action         = 'scheduled_task_history'
          item           = 'history'
          timestamp      = (To-ISO8601 $ev.TimeCreated)
          task_name      = $task.TaskName
          full_name      = $fullName
          path           = $task.TaskPath
          event_id       = $ev.Id
          result         = $result
        }) )
      }
    }catch{
    Write-Log "History load failed for ${fullName}: $($_.Exception.Message)" 'WARN'

    }
  }

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("Wrote {0} NDJSON record(s) to {1}" -f $lines.Count, $ARLog) 'INFO'
}
catch{
  Write-Log $_.Exception.Message 'ERROR'
  $err = New-NdjsonLine @{
    item           = 'error'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @($err) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally{
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
