function Start-Todo {
    <#
    .SYNOPSIS
        A PowerShell Todo application with CLI and interactive menu support.

    .DESCRIPTION
        Manages tasks stored in a JSON file with options to add, list, complete, remove, and edit tasks.
        Supports both command-line arguments and an interactive menu. Tasks include a priority field.
        Launches Notepad for entering descriptions in the menu and for CLI add/edit commands.

    .EXAMPLE
        Start-Todo
        Launches the interactive menu.

    .EXAMPLE
        Start-Todo -Command "add" -Category "Shopping" -Tags "urgent" -Priority "High"
        Adds a task via CLI, launching Notepad to enter the description.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet("add", "list", "done", "remove", "edit")]
        [string]$Command,

        [Parameter(Mandatory = $false)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [string]$Category,

        [Parameter(Mandatory = $false)]
        [string]$Tags,

        [Parameter(Mandatory = $false)]
        [int]$TaskId,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Low", "Medium", "High")]
        [string]$Priority
    )

    # Define constants
    $todoFile = Join-Path $PSScriptRoot "todos.json"

    # Initialize todo file if it doesn't exist
    if (-Not (Test-Path $todoFile)) {
        @() | ConvertTo-Json | Out-File $todoFile
    }

    # Helper Functions
    function Get-Todos {
        try {
            $content = Get-Content $todoFile -Raw | ConvertFrom-Json
            # Ensure the result is always an array
            if ($null -eq $content) {
                return @()
            }
            return @($content)
        } catch {
            Write-Error "Error reading todo file: $_"
            return @()
        }
    }

    function Save-Todos ($todos) {
        try {
            $todos | ConvertTo-Json -Depth 3 | Out-File $todoFile
        } catch {
            Write-Error "Error saving todos: $_"
        }
    }

    function Show-Task ($todo) {
        $status = if ($todo.Completed) { "[X]" } else { "[ ]" }
        $catText = if ($todo.Category) { "Category: $($todo.Category)" } else { "" }
        $tagsText = if ($todo.Tags -and $todo.Tags.Count -gt 0) { "Tags: $($todo.Tags -join ', ')" } else { "" }
        $priorityText = if ($todo.Priority) { "Priority: $($todo.Priority)" } else { "" }
        return "$($todo.Id). $status $($todo.Description) (Created: $($todo.Created)) $catText $tagsText $priorityText"
    }

    function Get-DescriptionFromNotepad ($initialText = "") {
        $tempFile = [System.IO.Path]::GetTempFileName() + ".txt"
        if ($initialText) {
            $initialText | Out-File $tempFile
        }
        Write-Host "Opening Notepad to enter description. Save and close Notepad to continue..." -ForegroundColor Yellow
        Start-Process notepad.exe $tempFile -Wait
        if (Test-Path $tempFile) {
            $desc = Get-Content $tempFile -Raw
            Remove-Item $tempFile
            return $desc.Trim()
        }
        return ""
    }

    # Core Functions
    function Add-Task ($desc, $cat = "", $tagList = @(), $priority = "Medium") {
        $todos = Get-Todos
        $newTask = [PSCustomObject]@{
            Id          = if ($todos) { ($todos | Measure-Object).Count + 1 } else { 1 }
            Description = $desc
            Completed   = $false
            Created     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Category    = $cat
            Tags        = $tagList
            Priority    = $priority
        }
        # Ensure $todos is an array before adding
        if ($null -eq $todos) {
            $todos = @()
        }
        $todos = @($todos) + @($newTask)
        Save-Todos $todos
        return $newTask
    }

    function Edit-Task ($id, $desc, $cat, $tagList, $priority) {
        $todos = Get-Todos
        $task = $todos | Where-Object { $_.Id -eq $id }
        if ($task) {
            if ($desc) { $task.Description = $desc }
            if ($null -ne $cat) { $task.Category = $cat }
            if ($null -ne $tagList) { $task.Tags = $tagList }
            if ($priority) { $task.Priority = $priority }
            Save-Todos $todos
            return $true
        }
        return $false
    }

    function Get-Tasks {
        $todos = Get-Todos
        if ($todos.Count -eq 0) {
            Write-Host "No tasks found." -ForegroundColor Yellow
        } else {
            $todos | ForEach-Object { Write-Host (Show-Task $_) }
        }
    }

    function Complete-Task ($id) {
        $todos = Get-Todos
        $task = $todos | Where-Object { $_.Id -eq $id }
        if ($task) {
            $task.Completed = $true
            Save-Todos $todos
            return $true
        }
        return $false
    }

    function Remove-Task ($id) {
        $todos = Get-Todos
        $newTodos = $todos | Where-Object { $_.Id -ne $id }
        if ($newTodos.Count -lt $todos.Count) {
            Save-Todos $newTodos
            return $true
        }
        return $false
    }

    # Menu System
    function Show-Menu {
        Clear-Host
        Write-Host "=== Todo List Manager ===" -ForegroundColor Cyan
        Write-Host "1. List Tasks" -ForegroundColor White
        Write-Host "2. Add Task" -ForegroundColor White
        Write-Host "3. Complete Task" -ForegroundColor White
        Write-Host "4. Remove Task" -ForegroundColor White
        Write-Host "5. Edit Task" -ForegroundColor White
        Write-Host "X. Exit" -ForegroundColor White
        Write-Host "=====================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Select an option (1-5, X): " -ForegroundColor Green -NoNewline
    }

    function Start-Menu {
        while ($true) {
            Show-Menu
            $choice = Read-Host
            Write-Host ""

            switch ($choice.ToUpper()) {
                "1" { 
                    Get-Tasks
                    Write-Host ""
                    Write-Host "Press Enter to continue..." -ForegroundColor Gray
                    Read-Host
                }
                "2" {
                    $desc = Get-DescriptionFromNotepad
                    if ($desc) {
                        Write-Host "Enter category (optional): " -ForegroundColor Green -NoNewline
                        $cat = Read-Host
                        Write-Host "Enter tags (comma-separated, optional): " -ForegroundColor Green -NoNewline
                        $tagsInput = Read-Host
                        Write-Host "Enter priority (Low/Medium/High, default is Medium): " -ForegroundColor Green -NoNewline
                        $priorityInput = Read-Host
                        $tags = if ($tagsInput) { $tagsInput -split "," | ForEach-Object { $_.Trim() } } else { @() }
                        $priority = if ($priorityInput -and $priorityInput -in "Low", "Medium", "High") { $priorityInput } 
                                    elseif ($priorityInput -and $priorityInput -in "low", "medium", "high") { $priorityInput.ToLower() | ForEach-Object { $_.Substring(0,1).ToUpper() + $_.Substring(1) } }
                                    else { "Medium" }
                        $task = Add-Task $desc $cat $tags $priority
                        Write-Host "Task added: $(Show-Task $task)" -ForegroundColor Green
                    } else {
                        Write-Host "Task description cannot be empty." -ForegroundColor Red
                    }
                    Write-Host ""
                    Write-Host "Press Enter to continue..." -ForegroundColor Gray
                    Read-Host
                }
                "3" {
                    Get-Tasks
                    Write-Host ""
                    Write-Host "Enter task ID to complete: " -ForegroundColor Green -NoNewline
                    $id = Read-Host
                    if ($id -and $id -match '^\d+$' -and (Complete-Task ([int]$id))) {
                        Write-Host "Task $id marked as completed." -ForegroundColor Green
                    } else {
                        Write-Host "Invalid task ID." -ForegroundColor Red
                    }
                    Write-Host ""
                    Write-Host "Press Enter to continue..." -ForegroundColor Gray
                    Read-Host
                }
                "4" {
                    Get-Tasks
                    Write-Host ""
                    Write-Host "Enter task ID to remove: " -ForegroundColor Green -NoNewline
                    $id = Read-Host
                    if ($id -and $id -match '^\d+$' -and (Remove-Task ([int]$id))) {
                        Write-Host "Task $id removed." -ForegroundColor Green
                    } else {
                        Write-Host "Invalid task ID." -ForegroundColor Red
                    }
                    Write-Host ""
                    Write-Host "Press Enter to continue..." -ForegroundColor Gray
                    Read-Host
                }
                "5" {
                    Get-Tasks
                    Write-Host ""
                    Write-Host "Enter task ID to edit: " -ForegroundColor Green -NoNewline
                    $id = Read-Host
                    if ($id -and $id -match '^\d+$') {
                        $todos = Get-Todos
                        $task = $todos | Where-Object { $_.Id -eq [int]$id }
                        if ($task) {
                            Write-Host "Current task: $(Show-Task $task)" -ForegroundColor Yellow
                            $desc = Get-DescriptionFromNotepad $task.Description
                            Write-Host "Enter new category (leave blank to keep unchanged, 'none' to clear): " -ForegroundColor Green -NoNewline
                            $cat = Read-Host
                            Write-Host "Enter new tags (comma-separated, leave blank to keep unchanged, 'none' to clear): " -ForegroundColor Green -NoNewline
                            $tagsInput = Read-Host
                            Write-Host "Enter new priority (Low/Medium/High, leave blank to keep unchanged): " -ForegroundColor Green -NoNewline
                            $priorityInput = Read-Host
                            $tags = if ($tagsInput -eq "none") { @() }
                                    elseif ($tagsInput) { $tagsInput -split "," | ForEach-Object { $_.Trim() } }
                                    else { $null }
                            $priority = if ($priorityInput -and $priorityInput -in "Low", "Medium", "High") { $priorityInput }
                                        elseif ($priorityInput -and $priorityInput -in "low", "medium", "high") { $priorityInput.ToLower() | ForEach-Object { $_.Substring(0,1).ToUpper() + $_.Substring(1) } }
                                        else { $null }
                            $cat = if ($cat -eq "none") { "" } else { $cat }
                            if (Edit-Task ([int]$id) $desc $cat $tags $priority) {
                                $updatedTask = $todos | Where-Object { $_.Id -eq [int]$id }
                                Write-Host "Task updated: $(Show-Task $updatedTask)" -ForegroundColor Green
                            } else {
                                Write-Host "Failed to update task." -ForegroundColor Red
                            }
                        } else {
                            Write-Host "Task $id not found." -ForegroundColor Red
                        }
                    } else {
                        Write-Host "Invalid task ID." -ForegroundColor Red
                    }
                    Write-Host ""
                    Write-Host "Press Enter to continue..." -ForegroundColor Gray
                    Read-Host
                }
                "X" { 
                    Write-Host "Goodbye!" -ForegroundColor Cyan
                    return 
                }
                default { 
                    Write-Host "Invalid choice. Please select 1-5 or X." -ForegroundColor Red
                    Write-Host ""
                    Write-Host "Press Enter to continue..." -ForegroundColor Gray
                    Read-Host
                }
            }
        }
    }

    # Process Parameters or Start Menu
    if (-not $PSBoundParameters.Count) {
        Start-Menu
    } else {
        switch ($Command.ToLower()) {
            "add" {
                $desc = if ($Description) { $Description } else { Get-DescriptionFromNotepad }
                if (-not $desc) { Write-Error "Description is required for add."; return }
                $tagsArray = if ($Tags) { $Tags -split "," | ForEach-Object { $_.Trim() } } else { @() }
                $priorityValue = if ($Priority) { $Priority } else { "Medium" }
                $task = Add-Task $desc $Category $tagsArray $priorityValue
                Write-Host "Task added: $(Show-Task $task)"
            }
            "edit" {
                if (-not $TaskId) { Write-Error "TaskId is required for edit."; return }
                $todos = Get-Todos
                $task = $todos | Where-Object { $_.Id -eq $TaskId }
                if (-not $task) { Write-Error "Task $TaskId not found."; return }
                $desc = if ($Description) { $Description } else { Get-DescriptionFromNotepad $task.Description }
                $tagsArray = if ($Tags) { $Tags -split "," | ForEach-Object { $_.Trim() } } else { $null }
                if (Edit-Task $TaskId $desc $Category $tagsArray $Priority) {
                    $updatedTask = $todos | Where-Object { $_.Id -eq $TaskId }
                    Write-Host "Task updated: $(Show-Task $updatedTask)"
                } else {
                    Write-Error "Failed to update task $TaskId."
                }
            }
            "list" { Get-Tasks }
            "done" {
                if (-not $TaskId) { Write-Error "TaskId is required for done."; return }
                if (Complete-Task $TaskId) {
                    Write-Host "Task $TaskId marked as completed."
                } else {
                    Write-Error "Task $TaskId not found."
                }
            }
            "remove" {
                if (-not $TaskId) { Write-Error "TaskId is required for remove."; return }
                if (Remove-Task $TaskId) {
                    Write-Host "Task $TaskId removed."
                } else {
                    Write-Error "Task $TaskId not found."
                }
            }
        }
    }
}

# To dot-source this, save as Todo.ps1 and run:
# . .\Todo.ps1
# Then use: Start-Todo