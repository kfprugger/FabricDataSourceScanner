#Requires -Version 7.0
#Requires -Modules Az.KeyVault
# Author: Joey Brakefield
# Date: 2025-01-09
# Description: Scans all datasources in a Microsoft Fabric environment using the Scanner API and uploads results to a Fabric Lakehouse of your choosing.

<#
.SYNOPSIS
    Scans all datasources in a Microsoft Fabric environment using the Scanner API.
.DESCRIPTION
    Uses an Azure Service Principal to authenticate and retrieve datasource information
    across all workspaces in a Fabric tenant. The client secret is retrieved from Azure Key Vault.
.NOTES
    Requires: 
    - Microsoft Fabric Admin API permissions for the service principal
    - Az.KeyVault module
    - Access to the specified Azure Key Vault
.PARAMETER TenantId
    The Azure AD Tenant ID for authentication. Defaults to AZURE_TENANT_ID environment variable.
.PARAMETER ClientId
    The Azure AD Client ID for authentication. Defaults to AZURE_CLIENT_ID environment variable.
.PARAMETER KeyVaultName
    The name of the Azure Key Vault containing the client secret.
.PARAMETER SecretName
    The name of the secret containing the client secret. Defaults to "fabric-scanner-secret".   
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId = $env:AZURE_TENANT_ID,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientId = $env:AZURE_CLIENT_ID,
    
    [Parameter(Mandatory = $true)]
    [string]$KeyVaultName,
    
    [Parameter(Mandatory = $false)]
    [string]$SecretName = "fabric-scanner-secret",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "./fabric-scan-results.json",
    
    [Parameter(Mandatory = $false)]
    [string]$LakehouseWorkspaceId,
    
    [Parameter(Mandatory = $false)]
    [string]$LakehouseId,
    
    [Parameter(Mandatory = $false)]
    [string]$NotebookPath = "$PSScriptRoot\scanner_results_to_lakehouse.ipynb"
)

#region Authentication

function Get-KeyVaultSecret {
    [CmdletBinding()]
    param(
        [string]$VaultName,
        [string]$SecretName
    )
    
    try {
        $secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -AsPlainText
        return $secret
    }
    catch {
        throw "Failed to retrieve secret '$SecretName' from Key Vault '$VaultName': $_"
    }
}

#endregion

#region Scanner API Functions

function Invoke-FabricApi {
    [CmdletBinding()]
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [string]$AccessToken,
        [object]$Body = $null
    )
    
    $baseUrl = "https://api.powerbi.com/v1.0/myorg"
    $uri = "$baseUrl/$Endpoint"
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    $params = @{
        Uri     = $uri
        Method  = $Method
        Headers = $headers
    }
    
    if ($Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 10)
    }
    
    try {
        return Invoke-RestMethod @params
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $errorMessage = $_.ErrorDetails.Message
        Write-Warning "API call failed ($statusCode): $errorMessage"
        throw
    }
}

function Get-ModifiedWorkspaces {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [datetime]$ModifiedSince = (Get-Date).AddDays(-30)
    )
    
    # Format as ISO-8601 with 'o' round-trip format (e.g., 2025-01-09T00:00:00.0000000Z)
    $modifiedSinceStr = $ModifiedSince.ToUniversalTime().ToString("o")
    $encodedDate = [System.Uri]::EscapeDataString($modifiedSinceStr)
    $endpoint = "admin/workspaces/modified?modifiedSince=$encodedDate"
    
    Write-Verbose "Fetching workspaces modified since $modifiedSinceStr"
    Write-Verbose "Encoded URL: $endpoint"
    return Invoke-FabricApi -Endpoint $endpoint -AccessToken $AccessToken
}

function Start-WorkspaceScan {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string[]]$WorkspaceIds,
        [bool]$GetArtifactUsers = $false,
        [bool]$DatasetExpressions = $true,
        [bool]$DatasetSchema = $true,
        [bool]$DatasourceDetails = $true,
        [bool]$LineageInfo = $true
    )
    
    $body = @{
        workspaces = $WorkspaceIds
    }
    
    $queryParams = @(
        "datasetExpressions=$($DatasetExpressions.ToString().ToLower())"
        "datasetSchema=$($DatasetSchema.ToString().ToLower())"
        "datasourceDetails=$($DatasourceDetails.ToString().ToLower())"
        "getArtifactUsers=$($GetArtifactUsers.ToString().ToLower())"
        "lineage=$($LineageInfo.ToString().ToLower())"
    )
    
    $endpoint = "admin/workspaces/getInfo?" + ($queryParams -join "&")
    
    Write-Verbose "Initiating scan for $($WorkspaceIds.Count) workspace(s)"
    return Invoke-FabricApi -Endpoint $endpoint -Method "POST" -AccessToken $AccessToken -Body $body
}

function Get-ScanStatus {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$ScanId
    )
    
    $endpoint = "admin/workspaces/scanStatus/$ScanId"
    return Invoke-FabricApi -Endpoint $endpoint -AccessToken $AccessToken
}

function Get-ScanResult {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$ScanId
    )
    
    $endpoint = "admin/workspaces/scanResult/$ScanId"
    return Invoke-FabricApi -Endpoint $endpoint -AccessToken $AccessToken
}

function Wait-ForScanCompletion {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$ScanId,
        [int]$MaxWaitSeconds = 300,
        [int]$PollIntervalSeconds = 5
    )
    
    $elapsed = 0
    
    while ($elapsed -lt $MaxWaitSeconds) {
        $status = Get-ScanStatus -AccessToken $AccessToken -ScanId $ScanId
        
        Write-Verbose "Scan status: $($status.status)"
        
        if ($status.status -eq "Succeeded") {
            return $true
        }
        elseif ($status.status -eq "Failed") {
            throw "Scan failed: $($status.error)"
        }
        
        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
    }
    
    throw "Scan timed out after $MaxWaitSeconds seconds"
}

#endregion

#region Lakehouse Functions

function Get-FabricAccessToken {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$Scope = "https://analysis.windows.net/powerbi/api/.default"
    )
    
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = $Scope
    }
    
    try {
        $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch {
        throw "Failed to acquire access token: $_"
    }
}

function Get-OneLakeAccessToken {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )
    
    # OneLake uses Azure Storage scope for file operations
    return Get-FabricAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope "https://storage.azure.com/.default"
}

function Get-FabricCoreApiToken {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )
    
    # Fabric Core API scope for Lakehouse table operations
    return Get-FabricAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope "https://api.fabric.microsoft.com/.default"
}

function Test-LakehouseAccess {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$WorkspaceId,
        [string]$LakehouseId
    )
    
    # Use Admin API to check workspace exists (SPN has admin permissions)
    $uri = "https://api.powerbi.com/v1.0/myorg/admin/groups/$WorkspaceId"
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        Write-Verbose "Workspace access verified via Admin API: $($response.name)"
        return @{
            HasAccess = $true
            WorkspaceName = $response.name
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Warning "Failed to access Workspace ($statusCode): $($_.ErrorDetails.Message)"
        return @{ HasAccess = $false }
    }
}

function ConvertTo-LakehouseRows {
    [CmdletBinding()]
    param(
        [object]$ScanResults,
        [datetime]$ScanDate
    )
    
    $rows = @()
    $scanDateStr = $ScanDate.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
    
    foreach ($workspace in $ScanResults.workspaces) {
        foreach ($dataset in $workspace.datasets) {
            if ($dataset.datasources -and $dataset.datasources.Count -gt 0) {
                foreach ($datasource in $dataset.datasources) {
                    $rows += [PSCustomObject]@{
                        scan_date            = $scanDateStr
                        workspace_id         = $workspace.id
                        workspace_name       = $workspace.name
                        workspace_type       = $workspace.type
                        workspace_state      = $workspace.state
                        dataset_id           = $dataset.id
                        dataset_name         = $dataset.name
                        dataset_configured_by = $dataset.configuredBy
                        dataset_created_date = $dataset.createdDate
                        datasource_type      = $datasource.datasourceType
                        datasource_id        = $datasource.datasourceId
                        gateway_id           = $datasource.gatewayId
                        connection_details   = ($datasource.connectionDetails | ConvertTo-Json -Compress -Depth 5)
                    }
                }
            }
            else {
                # Include datasets without datasources
                $rows += [PSCustomObject]@{
                    scan_date            = $scanDateStr
                    workspace_id         = $workspace.id
                    workspace_name       = $workspace.name
                    workspace_type       = $workspace.type
                    workspace_state      = $workspace.state
                    dataset_id           = $dataset.id
                    dataset_name         = $dataset.name
                    dataset_configured_by = $dataset.configuredBy
                    dataset_created_date = $dataset.createdDate
                    datasource_type      = $null
                    datasource_id        = $null
                    gateway_id           = $null
                    connection_details   = $null
                }
            }
        }
    }
    
    return $rows
}

function Write-ToOneLake {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$WorkspaceId,
        [string]$LakehouseId,
        [string]$FilePath,
        [byte[]]$Content
    )
    
    $baseUri = "https://onelake.dfs.fabric.microsoft.com"
    $fullPath = "$WorkspaceId/$LakehouseId/Files/$FilePath"
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/octet-stream"
    }
    
    # Create file
    $createUri = "$baseUri/$fullPath`?resource=file"
    try {
        Write-Verbose "Creating file at: $createUri"
        Invoke-RestMethod -Uri $createUri -Method Put -Headers $headers | Out-Null
        Write-Verbose "Created file: $FilePath"
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 409) {
            Write-Verbose "File already exists, will overwrite"
        }
        elseif ($statusCode -eq 403) {
            throw "Access denied to OneLake. The Service Principal must be added as a Member or Contributor to the workspace. Error: $($_.ErrorDetails.Message)"
        }
        else {
            Write-Verbose "Create file response: $($_.ErrorDetails.Message)"
        }
    }
    
    # Append content
    $appendUri = "$baseUri/$fullPath`?action=append&position=0"
    
    try {
        Write-Verbose "Appending content to: $appendUri"
        Invoke-RestMethod -Uri $appendUri -Method Patch -Headers $headers -Body $Content | Out-Null
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 403) {
            throw "Access denied to OneLake. The Service Principal must be added as a Member or Contributor to the workspace. Error: $($_.ErrorDetails.Message)"
        }
        throw "Failed to append content: $($_.ErrorDetails.Message)"
    }
    
    # Flush (finalize)
    $flushUri = "$baseUri/$fullPath`?action=flush&position=$($Content.Length)"
    try {
        Write-Verbose "Flushing file at: $flushUri"
        Invoke-RestMethod -Uri $flushUri -Method Patch -Headers $headers | Out-Null
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 403) {
            throw "Access denied to OneLake. The Service Principal must be added as a Member or Contributor to the workspace. Error: $($_.ErrorDetails.Message)"
        }
        throw "Failed to flush file: $($_.ErrorDetails.Message)"
    }
    
    Write-Verbose "File written successfully: $FilePath"
}

function Write-ToOneLakeTable {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$WorkspaceId,
        [string]$LakehouseId,
        [string]$SchemaName,
        [string]$TableName,
        [string]$FileName,
        [byte[]]$Content
    )
    
    $baseUri = "https://onelake.dfs.fabric.microsoft.com"
    # For schema-enabled Lakehouses, tables are at Tables/<schema>/<table>/
    $tablePath = "$WorkspaceId/$LakehouseId/Tables/$SchemaName/$TableName"
    $fullPath = "$tablePath/$FileName"
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/octet-stream"
    }
    
    # Create directory structure first
    $dirUri = "$baseUri/$tablePath`?resource=directory"
    try {
        Write-Verbose "Creating directory at: $dirUri"
        Invoke-RestMethod -Uri $dirUri -Method Put -Headers $headers | Out-Null
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -ne 409) {
            Write-Verbose "Directory creation response: $($_.ErrorDetails.Message)"
        }
    }
    
    # Create file
    $createUri = "$baseUri/$fullPath`?resource=file"
    try {
        Write-Verbose "Creating file at: $createUri"
        Invoke-RestMethod -Uri $createUri -Method Put -Headers $headers | Out-Null
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 403) {
            throw "Access denied to OneLake. Error: $($_.ErrorDetails.Message)"
        }
        Write-Verbose "Create file response: $($_.ErrorDetails.Message)"
    }
    
    # Append content
    $appendUri = "$baseUri/$fullPath`?action=append&position=0"
    try {
        Write-Verbose "Appending content to: $appendUri"
        Invoke-RestMethod -Uri $appendUri -Method Patch -Headers $headers -Body $Content | Out-Null
    }
    catch {
        throw "Failed to append content: $($_.ErrorDetails.Message)"
    }
    
    # Flush (finalize)
    $flushUri = "$baseUri/$fullPath`?action=flush&position=$($Content.Length)"
    try {
        Write-Verbose "Flushing file at: $flushUri"
        Invoke-RestMethod -Uri $flushUri -Method Patch -Headers $headers | Out-Null
    }
    catch {
        throw "Failed to flush file: $($_.ErrorDetails.Message)"
    }
    
    Write-Verbose "File written to table path successfully: $fullPath"
}

function Invoke-LakehouseTableLoad {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$WorkspaceId,
        [string]$LakehouseId,
        [string]$TableName,
        [string]$SourceFilePath,
        [string]$LoadMode = "Append"
    )
    
    # Use Fabric Core API endpoint for lakehouse table operations
    $uri = "https://api.fabric.microsoft.com/v1/workspaces/$WorkspaceId/lakehouses/$LakehouseId/tables/$TableName/load"
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    $body = @{
        relativePath = "Files/$SourceFilePath"
        pathType = "File"
        mode = $LoadMode
        formatOptions = @{
            format = "Csv"
            header = $true
            delimiter = ","
        }
    } | ConvertTo-Json -Depth 5
    
    Write-Verbose "Table load URI: $uri"
    Write-Verbose "Table load body: $body"
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body
        return $response
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $errorMessage = $_.ErrorDetails.Message
        throw "Failed to load table ($statusCode): $errorMessage"
    }
}

function Wait-ForTableLoadCompletion {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$OperationUrl,
        [int]$MaxWaitSeconds = 300,
        [int]$PollIntervalSeconds = 5
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }
    
    $elapsed = 0
    
    while ($elapsed -lt $MaxWaitSeconds) {
        try {
            $status = Invoke-RestMethod -Uri $OperationUrl -Method Get -Headers $headers
            Write-Verbose "Table load status: $($status.status)"
            
            if ($status.status -eq "Succeeded") {
                return $true
            }
            elseif ($status.status -eq "Failed") {
                throw "Table load failed: $($status.error.message)"
            }
        }
        catch {
            # If we can't get status, operation might have completed
            if ($_.Exception.Response.StatusCode.value__ -eq 404) {
                return $true
            }
            throw
        }
        
        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
    }
    
    throw "Table load timed out after $MaxWaitSeconds seconds"
}

#region Notebook Functions

function New-ScannerNotebook {
    <#
    .SYNOPSIS
        Creates the scanner results notebook file locally if it doesn't exist.
    .DESCRIPTION
        Generates a PySpark notebook with MERGE (upsert) logic for loading
        scanner results into a Lakehouse Delta table.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$NotebookPath
    )
    
    Write-Verbose "Creating scanner notebook at: $NotebookPath"
    
    $notebookContent = @{
        nbformat = 4
        nbformat_minor = 5
        metadata = @{
            kernel_info = @{
                name = "synapse_pyspark"
            }
            language_info = @{
                name = "python"
            }
        }
        cells = @(
            @{
                cell_type = "code"
                metadata = @{}
                source = @(
                    "from pyspark.sql import SparkSession`n",
                    "from delta.tables import DeltaTable`n",
                    "from pyspark.sql.functions import col`n",
                    "`n",
                    "# Read all staging CSV files`n",
                    "staging_path = `"Files/scanner_staging_*.csv`"`n",
                    "print(f`"Reading staging files from: {staging_path}`")`n",
                    "`n",
                    "try:`n",
                    "    df = spark.read.option(`"header`", `"true`").csv(staging_path)`n",
                    "    row_count = df.count()`n",
                    "    print(f`"Read {row_count} rows from staging CSV files`")`n",
                    "    `n",
                    "    if row_count > 0:`n",
                    "        # Show sample data`n",
                    "        print(`"\nSample data:`")`n",
                    "        df.show(5, truncate=False)`n",
                    "        print(f`"\nSchema:`")`n",
                    "        df.printSchema()`n",
                    "except Exception as e:`n",
                    "    print(f`"No staging files found or error reading: {e}`")`n",
                    "    row_count = 0"
                )
                outputs = @()
                execution_count = $null
            },
            @{
                cell_type = "code"
                metadata = @{}
                source = @(
                    "# Upsert (MERGE) logic - insert new records, update existing ones`n",
                    "table_name = `"dbo.scanner_results`"`n",
                    "# Use workspace_id + dataset_id as the key (NOT scan_date - it changes every run)`n",
                    "merge_keys = [`"workspace_id`", `"dataset_id`"]`n",
                    "`n",
                    "if row_count > 0:`n",
                    "    # Check if table exists`n",
                    "    table_exists = spark.catalog.tableExists(table_name)`n",
                    "    `n",
                    "    if not table_exists:`n",
                    "        # Create table with first load`n",
                    "        print(f`"Table {table_name} does not exist. Creating with initial data...`")`n",
                    "        df.write.format(`"delta`").mode(`"overwrite`").saveAsTable(table_name)`n",
                    "        print(f`"Created table {table_name} with {row_count} rows`")`n",
                    "    else:`n",
                    "        # Perform MERGE (upsert)`n",
                    "        print(f`"Table {table_name} exists. Performing MERGE (upsert)...`")`n",
                    "        `n",
                    "        delta_table = DeltaTable.forName(spark, table_name)`n",
                    "        `n",
                    "        # Build merge condition`n",
                    "        merge_condition = `" AND `".join([f`"target.{key} = source.{key}`" for key in merge_keys])`n",
                    "        `n",
                    "        # Get all columns for update`n",
                    "        update_dict = {col_name: f`"source.{col_name}`" for col_name in df.columns}`n",
                    "        insert_dict = {col_name: f`"source.{col_name}`" for col_name in df.columns}`n",
                    "        `n",
                    "        # Execute merge`n",
                    "        delta_table.alias(`"target`").merge(`n",
                    "            df.alias(`"source`"),`n",
                    "            merge_condition`n",
                    "        ).whenMatchedUpdate(`n",
                    "            set=update_dict`n",
                    "        ).whenNotMatchedInsert(`n",
                    "            values=insert_dict`n",
                    "        ).execute()`n",
                    "        `n",
                    "        print(f`"MERGE completed successfully`")`n",
                    "        `n",
                    "        # Show updated row count`n",
                    "        new_count = spark.table(table_name).count()`n",
                    "        print(f`"Table {table_name} now has {new_count} total rows`")`n",
                    "else:`n",
                    "    print(`"No data to load - skipping upsert`")"
                )
                outputs = @()
                execution_count = $null
            },
            @{
                cell_type = "code"
                metadata = @{}
                source = @(
                    "# Clean up staging files after successful load`n",
                    "if row_count > 0:`n",
                    "    import notebookutils`n",
                    "    `n",
                    "    print(`"Cleaning up staging files...`")`n",
                    "    files = notebookutils.fs.ls(`"Files/`")`n",
                    "    deleted_count = 0`n",
                    "    `n",
                    "    for f in files:`n",
                    "        if `"scanner_staging_`" in f.name and f.name.endswith(`".csv`"):`n",
                    "            notebookutils.fs.rm(f.path)`n",
                    "            print(f`"  Deleted: {f.name}`")`n",
                    "            deleted_count += 1`n",
                    "    `n",
                    "    print(f`"\nCleanup complete. Deleted {deleted_count} staging file(s).`")`n",
                    "else:`n",
                    "    print(`"No staging files to clean up.`")"
                )
                outputs = @()
                execution_count = $null
            },
            @{
                cell_type = "code"
                metadata = @{}
                source = @(
                    "# Final verification`n",
                    "if spark.catalog.tableExists(table_name):`n",
                    "    final_df = spark.table(table_name)`n",
                    "    print(f`"\n=== Final Table Summary ===`")`n",
                    "    print(f`"Table: {table_name}`")`n",
                    "    print(f`"Total rows: {final_df.count()}`")`n",
                    "    print(f`"\nRecent scan dates:`")`n",
                    "    final_df.select(`"scan_date`").distinct().orderBy(col(`"scan_date`").desc()).show(5)`n",
                    "else:`n",
                    "    print(f`"Table {table_name} does not exist yet.`")"
                )
                outputs = @()
                execution_count = $null
            },
            @{
                cell_type = "code"
                metadata = @{}
                source = @(
                    "# Query the table to display results`n",
                    "if spark.catalog.tableExists(table_name):`n",
                    "    print(`"=== Scanner Results Table Contents ===\n`")`n",
                    "    `n",
                    "    # Show all records ordered by workspace and dataset`n",
                    "    results_df = spark.sql(f`"`"`"`n",
                    "        SELECT `n",
                    "            scan_date,`n",
                    "            workspace_name,`n",
                    "            dataset_name,`n",
                    "            dataset_configured_by,`n",
                    "            datasource_type,`n",
                    "            connection_details`n",
                    "        FROM {table_name}`n",
                    "        ORDER BY workspace_name, dataset_name`n",
                    "    `"`"`")`n",
                    "    `n",
                    "    results_df.show(100, truncate=False)`n",
                    "    `n",
                    "    # Summary statistics`n",
                    "    print(`"\n=== Summary by Workspace ===`")`n",
                    "    spark.sql(f`"`"`"`n",
                    "        SELECT `n",
                    "            workspace_name,`n",
                    "            COUNT(*) as dataset_count,`n",
                    "            MAX(scan_date) as last_scan`n",
                    "        FROM {table_name}`n",
                    "        GROUP BY workspace_name`n",
                    "        ORDER BY workspace_name`n",
                    "    `"`"`").show(truncate=False)`n",
                    "else:`n",
                    "    print(f`"Table {table_name} does not exist.`")"
                )
                outputs = @()
                execution_count = $null
            }
        )
    }
    
    # Ensure directory exists
    $notebookDir = Split-Path -Parent $NotebookPath
    if ($notebookDir -and -not (Test-Path $notebookDir)) {
        New-Item -ItemType Directory -Path $notebookDir -Force | Out-Null
    }
    
    # Write notebook to file
    $notebookContent | ConvertTo-Json -Depth 20 | Set-Content -Path $NotebookPath -Encoding UTF8
    
    Write-Host "  Created notebook: $NotebookPath" -ForegroundColor Green
}

function Import-NotebookToFabric {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$WorkspaceId,
        [string]$NotebookPath,
        [string]$NotebookName = "Scanner Results to Lakehouse",
        [string]$LakehouseId
    )
    
    $uri = "https://api.fabric.microsoft.com/v1/workspaces/$WorkspaceId/items"
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    # Create notebook locally if it doesn't exist
    if (-not (Test-Path $NotebookPath)) {
        Write-Host "  Notebook not found locally. Creating..." -ForegroundColor Yellow
        New-ScannerNotebook -NotebookPath $NotebookPath
    }
    
    $notebookContent = Get-Content -Path $NotebookPath -Raw
    $notebook = $notebookContent | ConvertFrom-Json -Depth 20
    
    # Inject Lakehouse metadata into the notebook if LakehouseId is provided
    if ($LakehouseId) {
        Write-Verbose "Injecting Lakehouse metadata into notebook..."
        
        # Ensure metadata exists
        if (-not $notebook.metadata) {
            $notebook | Add-Member -NotePropertyName "metadata" -NotePropertyValue @{} -Force
        }
        
        # Add Fabric-specific lakehouse attachment metadata
        # This is the format Fabric expects for default lakehouse
        $notebook.metadata | Add-Member -NotePropertyName "dependencies" -NotePropertyValue @{
            lakehouse = @{
                default_lakehouse = $LakehouseId
                default_lakehouse_name = "scanner_lh"
                default_lakehouse_workspace_id = $WorkspaceId
            }
        } -Force
        
        # Also add trident metadata which Fabric uses internally
        $notebook.metadata | Add-Member -NotePropertyName "trident" -NotePropertyValue @{
            lakehouse = @{
                default_lakehouse = $LakehouseId
                known_lakehouses = @(
                    @{
                        id = $LakehouseId
                    }
                )
            }
        } -Force
        
        Write-Verbose "Lakehouse metadata injected: $LakehouseId"
    }
    
    # Convert back to JSON and encode
    $notebookJson = $notebook | ConvertTo-Json -Depth 20 -Compress
    $notebookBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($notebookJson))
    
    # Check if notebook already exists
    Write-Verbose "Checking for existing notebook '$NotebookName'..."
    $existingNotebook = $null
    try {
        $items = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        $existingNotebook = $items.value | Where-Object { $_.displayName -eq $NotebookName -and $_.type -eq "Notebook" }
    }
    catch {
        Write-Verbose "Could not list items: $($_.ErrorDetails.Message)"
    }
    
    if ($existingNotebook) {
        Write-Verbose "Notebook '$NotebookName' already exists (ID: $($existingNotebook.id)). Updating definition..."
        
        # Update existing notebook definition
        $updateUri = "https://api.fabric.microsoft.com/v1/workspaces/$WorkspaceId/items/$($existingNotebook.id)/updateDefinition"
        
        $updateBody = @{
            definition = @{
                parts = @(
                    @{
                        path = "notebook-content.ipynb"
                        payload = $notebookBase64
                        payloadType = "InlineBase64"
                    }
                )
            }
        } | ConvertTo-Json -Depth 10
        
        try {
            Invoke-RestMethod -Uri $updateUri -Method Post -Headers $headers -Body $updateBody | Out-Null
            Write-Verbose "Notebook definition updated"
            return $existingNotebook.id
        }
        catch {
            Write-Warning "Failed to update notebook definition: $($_.ErrorDetails.Message)"
            # Return existing ID anyway - we'll try to run it
            return $existingNotebook.id
        }
    }
    
    # Create new notebook with definition
    Write-Verbose "Creating new notebook '$NotebookName'..."
    
    $createBody = @{
        displayName = $NotebookName
        type = "Notebook"
        definition = @{
            format = "ipynb"
            parts = @(
                @{
                    path = "notebook-content.ipynb"
                    payload = $notebookBase64
                    payloadType = "InlineBase64"
                }
            )
        }
    } | ConvertTo-Json -Depth 10
    
    try {
        # Use WebRequest to capture Location header for 202 responses
        $webResponse = Invoke-WebRequest -Uri $uri -Method Post -Headers $headers -Body $createBody -ContentType "application/json"
        
        if ($webResponse.StatusCode -eq 202) {
            # Long-running operation - poll for completion
            $locationHeader = $webResponse.Headers["Location"]
            if ($locationHeader) {
                Write-Verbose "Operation accepted, polling for completion..."
                $operationUrl = if ($locationHeader -is [array]) { $locationHeader[0] } else { $locationHeader }
                
                # Poll for completion
                $maxWait = 120
                $elapsed = 0
                while ($elapsed -lt $maxWait) {
                    Start-Sleep -Seconds 2
                    $elapsed += 2
                    
                    try {
                        $opStatus = Invoke-RestMethod -Uri $operationUrl -Method Get -Headers $headers
                        Write-Verbose "Operation status: $($opStatus.status)"
                        
                        if ($opStatus.status -eq "Succeeded") {
                            # Get the notebook ID from the result
                            if ($opStatus.response -and $opStatus.response.id) {
                                return $opStatus.response.id
                            }
                            # Otherwise search for it by name
                            break
                        }
                        elseif ($opStatus.status -eq "Failed") {
                            throw "Notebook creation failed: $($opStatus.error | ConvertTo-Json -Compress)"
                        }
                    }
                    catch {
                        if ($_.Exception.Response.StatusCode.value__ -eq 404) {
                            # Operation completed, notebook should exist
                            break
                        }
                        Write-Verbose "Polling error: $($_.ErrorDetails.Message)"
                    }
                }
                
                # Search for the notebook by name
                Write-Verbose "Searching for created notebook..."
                Start-Sleep -Seconds 2
                $items = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
                $createdNotebook = $items.value | Where-Object { $_.displayName -eq $NotebookName -and $_.type -eq "Notebook" }
                if ($createdNotebook) {
                    Write-Verbose "Found notebook with ID: $($createdNotebook.id)"
                    return $createdNotebook.id
                }
            }
        }
        elseif ($webResponse.StatusCode -eq 201 -or $webResponse.StatusCode -eq 200) {
            $responseContent = $webResponse.Content | ConvertFrom-Json
            if ($responseContent.id) {
                Write-Verbose "Notebook created with ID: $($responseContent.id)"
                return $responseContent.id
            }
        }
        
        # Fallback: search for notebook by name
        Write-Verbose "Searching for notebook by name..."
        Start-Sleep -Seconds 2
        $items = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        $createdNotebook = $items.value | Where-Object { $_.displayName -eq $NotebookName -and $_.type -eq "Notebook" }
        if ($createdNotebook) {
            return $createdNotebook.id
        }
        
        throw "Notebook creation did not return an ID"
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $errorMessage = $_.ErrorDetails.Message
        throw "Failed to create notebook ($statusCode): $errorMessage"
    }
}

function Set-NotebookLakehouseAttachment {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$WorkspaceId,
        [string]$NotebookId,
        [string]$LakehouseId
    )
    
    # Get current notebook definition to modify it
    $getDefUri = "https://api.fabric.microsoft.com/v1/workspaces/$WorkspaceId/items/$NotebookId/getDefinition"
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    Write-Verbose "Getting notebook definition..."
    try {
        $definition = Invoke-RestMethod -Uri $getDefUri -Method Post -Headers $headers
    }
    catch {
        Write-Warning "Could not get notebook definition: $($_.ErrorDetails.Message)"
        return $false
    }
    
    # Find the notebook content part
    $contentPart = $definition.definition.parts | Where-Object { $_.path -like "*.ipynb" }
    if (-not $contentPart) {
        Write-Warning "Could not find notebook content in definition"
        return $false
    }
    
    # Decode the notebook content
    $notebookJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($contentPart.payload))
    $notebook = $notebookJson | ConvertFrom-Json -Depth 20
    
    # Add or update lakehouse attachment in metadata
    if (-not $notebook.metadata) {
        $notebook | Add-Member -NotePropertyName "metadata" -NotePropertyValue @{} -Force
    }
    
    # Fabric notebook lakehouse attachment format
    $notebook.metadata | Add-Member -NotePropertyName "dependencies" -NotePropertyValue @{
        lakehouse = @{
            default_lakehouse = $LakehouseId
            default_lakehouse_name = "scanner_lh"
            default_lakehouse_workspace_id = $WorkspaceId
        }
    } -Force
    
    # Add trident metadata for Fabric
    $notebook.metadata | Add-Member -NotePropertyName "trident" -NotePropertyValue @{
        lakehouse = @{
            default_lakehouse = $LakehouseId
            known_lakehouses = @(
                @{
                    id = $LakehouseId
                }
            )
        }
    } -Force
    
    # Re-encode and update
    $updatedNotebookJson = $notebook | ConvertTo-Json -Depth 20 -Compress
    $updatedBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($updatedNotebookJson))
    
    $updateUri = "https://api.fabric.microsoft.com/v1/workspaces/$WorkspaceId/items/$NotebookId/updateDefinition"
    
    $updateBody = @{
        definition = @{
            parts = @(
                @{
                    path = $contentPart.path
                    payload = $updatedBase64
                    payloadType = "InlineBase64"
                }
            )
        }
    } | ConvertTo-Json -Depth 10
    
    Write-Verbose "Updating notebook with Lakehouse attachment..."
    try {
        Invoke-RestMethod -Uri $updateUri -Method Post -Headers $headers -Body $updateBody | Out-Null
        Write-Verbose "Lakehouse attachment added"
        return $true
    }
    catch {
        Write-Warning "Could not update notebook with Lakehouse attachment: $($_.ErrorDetails.Message)"
        return $false
    }
}

function Start-NotebookJob {
    [CmdletBinding()]
    param(
        [string]$AccessToken,
        [string]$WorkspaceId,
        [string]$NotebookId,
        [int]$MaxWaitSeconds = 600,
        [int]$PollIntervalSeconds = 10
    )
    
    $runUri = "https://api.fabric.microsoft.com/v1/workspaces/$WorkspaceId/items/$NotebookId/jobs/instances?jobType=RunNotebook"
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    Write-Verbose "Starting notebook job..."
    $jobId = $null
    
    try {
        # Use Invoke-WebRequest to capture headers from 202 response
        $webResponse = Invoke-WebRequest -Uri $runUri -Method Post -Headers $headers -ContentType "application/json"
        
        if ($webResponse.StatusCode -eq 202) {
            # Extract job ID from Location header
            $locationHeader = $webResponse.Headers["Location"]
            if ($locationHeader) {
                $locationUrl = if ($locationHeader -is [array]) { $locationHeader[0] } else { $locationHeader }
                $jobId = ($locationUrl -split '/')[-1]
                Write-Verbose "Job accepted, ID from Location header: $jobId"
            }
        }
        elseif ($webResponse.StatusCode -eq 200 -or $webResponse.StatusCode -eq 201) {
            $responseContent = $webResponse.Content | ConvertFrom-Json
            $jobId = $responseContent.id
            Write-Verbose "Job started with ID: $jobId"
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 202) {
            # Try to get Location header from exception response
            try {
                $locationHeader = $_.Exception.Response.Headers.Location
                if ($locationHeader) {
                    $jobId = ($locationHeader.ToString() -split '/')[-1]
                    Write-Verbose "Job accepted (from exception), ID: $jobId"
                }
            }
            catch {
                Write-Verbose "Could not extract job ID from 202 response"
            }
        }
        else {
            throw "Failed to start notebook job ($statusCode): $($_.ErrorDetails.Message)"
        }
    }
    
    # Poll for completion if we have a job ID
    if ($jobId) {
        $statusUri = "https://api.fabric.microsoft.com/v1/workspaces/$WorkspaceId/items/$NotebookId/jobs/instances/$jobId"
        $elapsed = 0
        
        Write-Verbose "Polling job status at: $statusUri"
        
        while ($elapsed -lt $MaxWaitSeconds) {
            Start-Sleep -Seconds $PollIntervalSeconds
            $elapsed += $PollIntervalSeconds
            
            try {
                $status = Invoke-RestMethod -Uri $statusUri -Method Get -Headers $headers
                Write-Verbose "Job status ($elapsed sec): $($status.status)"
                
                if ($status.status -eq "Completed") {
                    return @{
                        Success = $true
                        JobId = $jobId
                        Status = "Completed"
                    }
                }
                elseif ($status.status -eq "Failed") {
                    return @{
                        Success = $false
                        JobId = $jobId
                        Status = "Failed"
                        Error = $status.failureReason
                    }
                }
                elseif ($status.status -eq "Cancelled") {
                    return @{
                        Success = $false
                        JobId = $jobId
                        Status = "Cancelled"
                    }
                }
            }
            catch {
                Write-Verbose "Could not get job status: $($_.ErrorDetails.Message)"
            }
        }
        
        return @{
            Success = $false
            JobId = $jobId
            Status = "Timeout"
            Error = "Job did not complete within $MaxWaitSeconds seconds"
        }
    }
    
    # If no job ID, assume it ran synchronously
    return @{
        Success = $true
        JobId = $null
        Status = "Completed"
    }
}

#endregion

function Write-ToLakehouse {
    [CmdletBinding()]
    param(
        [string]$FabricCoreToken,
        [string]$OneLakeToken,
        [string]$WorkspaceId,
        [string]$LakehouseId,
        [object]$ScanResults,
        [datetime]$ScanDate,
        [string]$TableName = "scanner_results",
        [string]$SchemaName = "dbo",
        [string]$NotebookPath
    )
    
    Write-Host "Preparing data for Lakehouse..." -ForegroundColor Yellow
    
    # Convert to flattened rows
    $rows = ConvertTo-LakehouseRows -ScanResults $ScanResults -ScanDate $ScanDate
    
    if ($rows.Count -eq 0) {
        Write-Warning "No rows to write to Lakehouse"
        return
    }
    
    Write-Host "  Rows to write: $($rows.Count)" -ForegroundColor Cyan
    
    # Generate unique filename with timestamp
    $timestamp = $ScanDate.ToUniversalTime().ToString("yyyyMMdd_HHmmss")
    $csvFileName = "scanner_staging_$timestamp.csv"
    
    # Convert to CSV
    $csvContent = ($rows | ConvertTo-Csv -NoTypeInformation) -join "`n"
    $csvBytes = [System.Text.Encoding]::UTF8.GetBytes($csvContent)
    
    # Upload CSV to OneLake Files (uses Storage token)
    Write-Host "Uploading data to OneLake..." -ForegroundColor Yellow
    Write-ToOneLake -AccessToken $OneLakeToken -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId -FilePath $csvFileName -Content $csvBytes
    Write-Host "  File uploaded: $csvFileName" -ForegroundColor Green
    
    # Try standard table load first, fall back to schema-enabled approach if needed
    Write-Host "Loading data into table '$TableName'..." -ForegroundColor Yellow
    
    $isSchemaEnabled = $false
    try {
        $loadResponse = Invoke-LakehouseTableLoad -AccessToken $FabricCoreToken -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId -TableName $TableName -SourceFilePath $csvFileName -LoadMode "Append"
        
        if ($loadResponse) {
            Write-Verbose "Load operation initiated"
        }
        
        Write-Host "  Data loaded successfully into table '$TableName'" -ForegroundColor Green
        
        # Clean up staging file after successful load
        try {
            $deleteUri = "https://onelake.dfs.fabric.microsoft.com/$WorkspaceId/$LakehouseId/Files/$csvFileName"
            $deleteHeaders = @{ "Authorization" = "Bearer $OneLakeToken" }
            Invoke-RestMethod -Uri $deleteUri -Method Delete -Headers $deleteHeaders | Out-Null
            Write-Verbose "Staging file cleaned up: $csvFileName"
        }
        catch {
            Write-Verbose "Could not clean up staging file: $($_.ErrorDetails.Message)"
        }
    }
    catch {
        if ($_.Exception.Message -like "*UnsupportedOperationForSchemasEnabledLakehouse*" -or $_.Exception.Message -like "*schemas enabled*") {
            $isSchemaEnabled = $true
            Write-Host "  Lakehouse has schemas enabled - using notebook for UPSERT load." -ForegroundColor Yellow
            
            if ($NotebookPath) {
                Write-Host "  Importing notebook to Fabric with Lakehouse attachment..." -ForegroundColor Yellow
                
                try {
                    # Import the notebook with Lakehouse metadata embedded (creates locally if needed)
                    $notebookId = Import-NotebookToFabric -AccessToken $FabricCoreToken -WorkspaceId $WorkspaceId -NotebookPath $NotebookPath -NotebookName "Scanner Results to Lakehouse" -LakehouseId $LakehouseId
                    Write-Host "  Notebook imported/updated (ID: $notebookId)" -ForegroundColor Green
                    
                    # Run the notebook
                    Write-Host "  Running notebook to load data..." -ForegroundColor Yellow
                    $jobResult = Start-NotebookJob -AccessToken $FabricCoreToken -WorkspaceId $WorkspaceId -NotebookId $notebookId -MaxWaitSeconds 600
                    
                    if ($jobResult.Success) {
                        Write-Host "  Notebook completed successfully!" -ForegroundColor Green
                        Write-Host "  Data upserted into '$SchemaName.$TableName'" -ForegroundColor Cyan
                    }
                    else {
                        Write-Warning "  Notebook job status: $($jobResult.Status)"
                        if ($jobResult.Error) {
                            Write-Warning "  Error: $($jobResult.Error)"
                        }
                        Write-Host "  Staging file remains: Files/$csvFileName" -ForegroundColor Yellow
                        Write-Host "  Please run notebook 'Scanner Results to Lakehouse' manually in Fabric portal." -ForegroundColor Yellow
                    }
                }
                catch {
                    Write-Warning "Failed to import/run notebook: $($_.Exception.Message)"
                    Write-Host "  CSV staged: Files/$csvFileName" -ForegroundColor Cyan
                    Write-Host "  Please run notebook 'Scanner Results to Lakehouse' manually in Fabric portal." -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "  CSV staged: Files/$csvFileName" -ForegroundColor Cyan
                Write-Host "  NotebookPath parameter not specified" -ForegroundColor Yellow
                Write-Host "  Please create and run a notebook manually to load into '$SchemaName.$TableName'" -ForegroundColor Yellow
            }
        }
        else {
            throw
        }
    }
    
    Write-Host "  Total rows written: $($rows.Count)" -ForegroundColor Cyan
    
    return @{
        RowCount = $rows.Count
        StagingFile = $csvFileName
        IsSchemaEnabled = $isSchemaEnabled
        TableName = if ($isSchemaEnabled) { "$SchemaName.$TableName" } else { $TableName }
    }
}

#endregion

#region Main Execution

function Start-FabricDatasourceScan {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$KeyVaultName,
        [string]$SecretName,
        [string]$OutputPath,
        [string]$LakehouseWorkspaceId,
        [string]$LakehouseId,
        [string]$NotebookPath,
        [int]$BatchSize = 100
    )
    
    Write-Host "Starting Fabric datasource scan..." -ForegroundColor Cyan
    
    # Retrieve client secret from Key Vault
    Write-Host "Retrieving client secret from Key Vault '$KeyVaultName'..." -ForegroundColor Yellow
    $ClientSecret = Get-KeyVaultSecret -VaultName $KeyVaultName -SecretName $SecretName
    Write-Host "Secret retrieved successfully" -ForegroundColor Green
    
    # Check Lakehouse access if parameters provided
    $writeLakehouse = $false
    $lakehouseInfo = $null
    $oneLakeToken = $null
    
    if ($LakehouseWorkspaceId -and $LakehouseId) {
        Write-Host "Checking Lakehouse workspace access..." -ForegroundColor Yellow
        
        # Get Power BI token for Admin API calls (workspace verification)
        $pbiToken = Get-FabricAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope "https://analysis.windows.net/powerbi/api/.default"
        
        $lakehouseInfo = Test-LakehouseAccess -AccessToken $pbiToken -WorkspaceId $LakehouseWorkspaceId -LakehouseId $LakehouseId
        
        if ($lakehouseInfo.HasAccess) {
            Write-Host "  Workspace access confirmed: $($lakehouseInfo.WorkspaceName)" -ForegroundColor Green
            $writeLakehouse = $true
            
            # Get OneLake token for file operations (Storage scope)
            Write-Host "  Acquiring OneLake token (Storage scope)..." -ForegroundColor Yellow
            $oneLakeToken = Get-OneLakeAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
            Write-Host "  OneLake token acquired" -ForegroundColor Green
            
            # Get Fabric Core API token for table operations
            Write-Host "  Acquiring Fabric Core API token..." -ForegroundColor Yellow
            $fabricCoreToken = Get-FabricCoreApiToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
            Write-Host "  Fabric Core API token acquired" -ForegroundColor Green
        }
        else {
            Write-Warning "Service Principal does not have access to the specified workspace. Results will only be saved to JSON."
        }
    }
    
    # Authenticate for Power BI API
    Write-Host "Authenticating with service principal..." -ForegroundColor Yellow
    $accessToken = Get-FabricAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    Write-Host "Authentication successful" -ForegroundColor Green
    
    # Get modified workspaces
    Write-Host "Fetching workspaces..." -ForegroundColor Yellow
    $workspaces = Get-ModifiedWorkspaces -AccessToken $accessToken -ModifiedSince (Get-Date).AddDays(-30)
    
    if (-not $workspaces -or $workspaces.Count -eq 0) {
        Write-Warning "No workspaces found"
        return
    }
    
    Write-Host "Found $($workspaces.Count) workspace(s)" -ForegroundColor Green
    
    # Process workspaces in batches (API limit is 100 per request)
    $allResults = @()
    $workspaceIds = $workspaces | ForEach-Object { $_.id }
    
    for ($i = 0; $i -lt $workspaceIds.Count; $i += $BatchSize) {
        $batch = $workspaceIds[$i..([Math]::Min($i + $BatchSize - 1, $workspaceIds.Count - 1))]
        $batchNum = [Math]::Floor($i / $BatchSize) + 1
        $totalBatches = [Math]::Ceiling($workspaceIds.Count / $BatchSize)
        
        Write-Host "Processing batch $batchNum of $totalBatches ($($batch.Count) workspaces)..." -ForegroundColor Yellow
        
        # Start scan
        $scanResponse = Start-WorkspaceScan -AccessToken $accessToken -WorkspaceIds $batch
        $scanId = $scanResponse.id
        
        Write-Host "Scan initiated with ID: $scanId" -ForegroundColor Cyan
        
        # Wait for completion
        Write-Host "Waiting for scan to complete..." -ForegroundColor Yellow
        Wait-ForScanCompletion -AccessToken $accessToken -ScanId $scanId -Verbose:$VerbosePreference
        
        # Get results
        Write-Host "Retrieving scan results..." -ForegroundColor Yellow
        $result = Get-ScanResult -AccessToken $accessToken -ScanId $scanId
        $allResults += $result.workspaces
        
        # Brief pause between batches to respect rate limits
        if ($i + $BatchSize -lt $workspaceIds.Count) {
            Start-Sleep -Seconds 2
        }
    }
    
    # Extract datasource information
    Write-Host "Processing datasource information..." -ForegroundColor Yellow
    
    $datasourceSummary = @{
        scanDate       = (Get-Date).ToUniversalTime().ToString("o")
        totalWorkspaces = $allResults.Count
        workspaces     = @()
    }
    
    foreach ($workspace in $allResults) {
        $workspaceInfo = @{
            id          = $workspace.id
            name        = $workspace.name
            type        = $workspace.type
            state       = $workspace.state
            datasets    = @()
            dataflows   = @()
            reports     = @()
        }
        
        # Process datasets and their datasources
        foreach ($dataset in $workspace.datasets) {
            $datasetInfo = @{
                id              = $dataset.id
                name            = $dataset.name
                configuredBy    = $dataset.configuredBy
                createdDate     = $dataset.createdDate
                contentProviderType = $dataset.contentProviderType
                datasources     = @()
                tables          = @()
                expressions     = @()
            }
            
            # Datasources
            if ($dataset.datasources) {
                foreach ($ds in $dataset.datasources) {
                    $datasetInfo.datasources += @{
                        datasourceType    = $ds.datasourceType
                        connectionDetails = $ds.connectionDetails
                        datasourceId      = $ds.datasourceId
                        gatewayId         = $ds.gatewayId
                    }
                }
            }
            
            # Tables (schema info)
            if ($dataset.tables) {
                foreach ($table in $dataset.tables) {
                    $datasetInfo.tables += @{
                        name    = $table.name
                        columns = $table.columns | ForEach-Object {
                            @{
                                name     = $_.name
                                dataType = $_.dataType
                            }
                        }
                        source  = $table.source
                    }
                }
            }
            
            # Expressions (M queries)
            if ($dataset.expressions) {
                $datasetInfo.expressions = $dataset.expressions
            }
            
            $workspaceInfo.datasets += $datasetInfo
        }
        
        # Process dataflows
        foreach ($dataflow in $workspace.dataflows) {
            $dataflowInfo = @{
                objectId    = $dataflow.objectId
                name        = $dataflow.name
                configuredBy = $dataflow.configuredBy
                datasources = @()
            }
            
            if ($dataflow.datasources) {
                foreach ($ds in $dataflow.datasources) {
                    $dataflowInfo.datasources += @{
                        datasourceType    = $ds.datasourceType
                        connectionDetails = $ds.connectionDetails
                    }
                }
            }
            
            $workspaceInfo.dataflows += $dataflowInfo
        }
        
        # Process reports
        foreach ($report in $workspace.reports) {
            $workspaceInfo.reports += @{
                id          = $report.id
                name        = $report.name
                datasetId   = $report.datasetId
                createdDateTime = $report.createdDateTime
            }
        }
        
        $datasourceSummary.workspaces += $workspaceInfo
    }
    
    # Calculate summary statistics
    $totalDatasets = ($datasourceSummary.workspaces | ForEach-Object { $_.datasets.Count } | Measure-Object -Sum).Sum
    $totalDatasources = ($datasourceSummary.workspaces | ForEach-Object { 
        $_.datasets | ForEach-Object { $_.datasources.Count } 
    } | Measure-Object -Sum).Sum
    
    $datasourceSummary.summary = @{
        totalDatasets    = $totalDatasets
        totalDatasources = $totalDatasources
        datasourceTypes  = ($datasourceSummary.workspaces | ForEach-Object { 
            $_.datasets | ForEach-Object { 
                $_.datasources | ForEach-Object { $_.datasourceType } 
            } 
        } | Group-Object | ForEach-Object { 
            @{ type = $_.Name; count = $_.Count } 
        })
    }
    
    # Export results to JSON
    $datasourceSummary | ConvertTo-Json -Depth 20 | Out-File -FilePath $OutputPath -Encoding utf8
    
    Write-Host "`nScan complete!" -ForegroundColor Green
    Write-Host "Results saved to: $OutputPath" -ForegroundColor Cyan
    
    # Write to Lakehouse if access was confirmed
    if ($writeLakehouse) {
        Write-Host "`nWriting results to Lakehouse..." -ForegroundColor Cyan
        try {
            Write-ToLakehouse -FabricCoreToken $fabricCoreToken -OneLakeToken $oneLakeToken -WorkspaceId $LakehouseWorkspaceId -LakehouseId $LakehouseId -ScanResults $datasourceSummary -ScanDate (Get-Date) -NotebookPath $NotebookPath
        }
        catch {
            Write-Warning "Failed to write to Lakehouse: $_"
        }
    }
    
    Write-Host "`nSummary:" -ForegroundColor Yellow
    Write-Host "  Workspaces scanned: $($datasourceSummary.totalWorkspaces)"
    Write-Host "  Total datasets: $totalDatasets"
    Write-Host "  Total datasources: $totalDatasources"
    
    if ($datasourceSummary.summary.datasourceTypes) {
        Write-Host "`nDatasource types:" -ForegroundColor Yellow
        foreach ($type in $datasourceSummary.summary.datasourceTypes) {
            Write-Host "  $($type.type): $($type.count)"
        }
    }
    
    return $datasourceSummary
}

# Execute
$params = @{
    TenantId             = $TenantId
    ClientId             = $ClientId
    KeyVaultName         = $KeyVaultName
    SecretName           = $SecretName
    OutputPath           = $OutputPath
    LakehouseWorkspaceId = $LakehouseWorkspaceId
    LakehouseId          = $LakehouseId
    NotebookPath         = $NotebookPath
}

$results = Start-FabricDatasourceScan @params -Verbose