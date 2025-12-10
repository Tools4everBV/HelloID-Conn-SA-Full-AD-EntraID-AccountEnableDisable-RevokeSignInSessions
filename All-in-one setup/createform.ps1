# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Active Directory") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> EntraAppId
$tmpName = @'
EntraAppId
'@ 
$tmpValue = @'
<appid>
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> EntraTenantId
$tmpName = @'
EntraTenantId
'@ 
$tmpValue = @'
<tenantid>
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> EntraCertPassword
$tmpName = @'
EntraCertPassword
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #4 >> EntraBase64
$tmpName = @'
EntraBase64
'@ 
$tmpValue = @'
<BASE64_ENCODED_CERTIFICATE>
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #5 >> ADusersSearchOU
$tmpName = @'
ADusersSearchOU
'@ 
$tmpValue = @'
[     {         "OU": "OU=klant,DC=test,DC=local"     },     {         "OU": "OU=User Accounts,OU=klant,DC=test,DC=local"     } ]
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter()][String][AllowEmptyString()]$DatasourceRunInCloud,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
                runInCloud         = $DatasourceRunInCloud;
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}


<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "AD-Entra-user-generate-table-attributes-basic-deactivate" #>
$tmpPsScript = @'
try {
    $userPrincipalName = $dataSource.selectedUser.UserPrincipalName
    Write-Information "Searching AD user [$userPrincipalName]"
     
    $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName } -Properties displayname, samaccountname, userPrincipalName, mail, employeeID, Enabled | Select-Object displayname, samaccountname, userPrincipalName, mail, employeeID, Enabled
    Write-Information -Message "Finished searching AD user [$userPrincipalName]"
     
    foreach($tmp in $adUser.psObject.properties)
    {
        $returnObject = @{name=$tmp.Name; value=$tmp.value}
        Write-Output $returnObject
    }
     
    Write-Information "Finished retrieving AD user [$userPrincipalName] basic attributes"
} catch {
    Write-Error "Error retrieving AD user [$userPrincipalName] basic attributes. Error: $($_.Exception.Message)"
}
'@ 
$tmpModel = @'
[{"key":"value","type":0},{"key":"name","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedUser","type":0,"options":1}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
AD-Entra-user-generate-table-attributes-basic-deactivate
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "False" -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "AD-Entra-user-generate-table-attributes-basic-deactivate" #>

<# Begin: DataSource "AD-Entra-user-generate-table-wildcard-deactivate" #>
$tmpPsScript = @'
try {
    $searchValue = $dataSource.searchUser
    $searchQuery = "*$searchValue*"
    $searchOUs = $ADusersSearchOU
     
     
    if([String]::IsNullOrEmpty($searchValue) -eq $true){
        return
    }else{
        Write-Information "SearchQuery: $searchQuery"
        Write-Information "SearchBase: $searchOUs"
         
        $ous = $searchOUs | ConvertFrom-Json
        $users = foreach($item in $ous) {
            Get-ADUser -Filter {Name -like $searchQuery -or DisplayName -like $searchQuery -or userPrincipalName -like $searchQuery -or mail -like $searchQuery} -SearchBase $item.ou -properties SamAccountName, displayName, UserPrincipalName, Description, company, Department, Title
        }
         
        $users = $users | Sort-Object -Property DisplayName
        $resultCount = @($users).Count
        Write-Information "Result count: $resultCount"
         
        if($resultCount -gt 0){
            foreach($user in $users){
                $returnObject = @{SamAccountName=$user.SamAccountName; displayName=$user.displayName; UserPrincipalName=$user.UserPrincipalName; Description=$user.Description; Company=$user.company; Department=$user.Department; Title=$user.Title;}
                Write-Output $returnObject
            }
        }
    }
} catch {
    $msg = "Error searching AD user [$searchValue]. Error: $($_.Exception.Message)"
    Write-Error $msg
}
'@ 
$tmpModel = @'
[{"key":"Description","type":0},{"key":"SamAccountName","type":0},{"key":"Title","type":0},{"key":"Company","type":0},{"key":"Department","type":0},{"key":"displayName","type":0},{"key":"UserPrincipalName","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"searchUser","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
AD-Entra-user-generate-table-wildcard-deactivate
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "False" -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "AD-Entra-user-generate-table-wildcard-deactivate" #>

<# Begin: DataSource "AD-Entra-user-get-attribute-enabled-deactivate" #>
$tmpPsScript = @'
$UserPrincipalName = $datasource.selectedUser.UserPrincipalName
Write-information "Searching AD user [$userPrincipalName]"

try {
    $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName } -Properties enabled | select enabled
    Write-information "Found AD user [$userPrincipalName]"
    
    $enabled = $adUser.enabled    
    Write-information "Account enabled: $enabled"    
    Write-output @{ enabled = $enabled }
} catch {
    Write-error "Error retrieving AD user [$userPrincipalName] account status. Error: $($_.Exception.Message)"
    return
}
'@ 
$tmpModel = @'
[{"key":"enabled","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedUser","type":0,"options":1}]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
AD-Entra-user-get-attribute-enabled-deactivate
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -DataSourceRunInCloud "False" -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "AD-Entra-user-get-attribute-enabled-deactivate" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "AD & Entra Account - (De)Activate and revoke SignInSessions" #>
$tmpSchema = @"
[{"label":"Select user account","fields":[{"key":"searchfield","templateOptions":{"label":"Search","placeholder":"Username or email address"},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"gridUsers","templateOptions":{"label":"Select user","required":true,"grid":{"columns":[{"headerName":"DisplayName","field":"displayName"},{"headerName":"UserPrincipalName","field":"UserPrincipalName"},{"headerName":"Department","field":"Department"},{"headerName":"Title","field":"Title"},{"headerName":"Description","field":"Description"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchUser","otherFieldValue":{"otherFieldKey":"searchfield"}}]}},"useFilter":false,"allowCsvDownload":true},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"(De)activate","fields":[{"key":"gridDetails","templateOptions":{"label":"Basic attributes","required":false,"grid":{"columns":[{"headerName":"Name","field":"name"},{"headerName":"Value","field":"value"}],"height":350,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"selectedUser","otherFieldValue":{"otherFieldKey":"gridUsers"}}]}},"useFilter":false,"allowCsvDownload":true},"type":"grid","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true},{"key":"enabled","templateOptions":{"label":"AD account status","useSwitch":true,"checkboxLabel":"active","useDataSource":true,"displayField":"enabled","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[{"propertyName":"selectedUser","otherFieldValue":{"otherFieldKey":"gridUsers"}}]}},"useFilter":false},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
AD & Entra Account - (De)Activate and revoke SignInSessions
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
    foreach($group in $delegatedFormAccessGroupNames) {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
            $delegatedFormAccessGroupGuid = $response.groupGuid
            $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
            
            Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
        } catch {
            Write-Error "HelloID (access)group '$group', message: $_"
        }
    }
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $response = $response | Where-Object {$_.name.en -eq $category}
        
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
AD & Entra Account - (De)Activate and revoke SignInSessions
'@
$tmpTask = @'
{"name":"AD & Entra Account - (De)Activate and revoke SignInSessions","script":"$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n# variables configured in form\r\n$userPrincipalName = $form.gridUsers.UserPrincipalName\r\n$blnenabled = $form.enabled\r\n$accountPropertiesToQuery = @(\"id\")\r\n\r\n#region functions\r\nfunction Get-MSEntraCertificate {\r\n    [CmdletBinding()]\r\n    param()\r\n    try {\r\n        $rawCertificate = [system.convert]::FromBase64String($EntraBase64)\r\n        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraCertPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)\r\n        Write-Output $certificate\r\n    }\r\n    catch {\r\n        $PSCmdlet.ThrowTerminatingError($_)\r\n    }\r\n}\r\n\r\nfunction Get-MSEntraAccessToken {\r\n    [CmdletBinding()]\r\n    param(\r\n        [Parameter(Mandatory)]\r\n        $Certificate\r\n    )\r\n    try {\r\n        # Get the DER encoded bytes of the certificate\r\n        $derBytes = $Certificate.RawData\r\n\r\n        # Compute the SHA-256 hash of the DER encoded bytes\r\n        $sha256 = [System.Security.Cryptography.SHA256]::Create()\r\n        $hashBytes = $sha256.ComputeHash($derBytes)\r\n        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')\r\n\r\n        # Create a JWT (JSON Web Token) header\r\n        $header = @{\r\n            'alg'      = 'RS256'\r\n            'typ'      = 'JWT'\r\n            'x5t#S256' = $base64Thumbprint\r\n        } | ConvertTo-Json\r\n        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))\r\n\r\n        # Calculate the Unix timestamp (seconds since 1970-01-01T00:00:00Z) for 'exp', 'nbf' and 'iat'\r\n        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)\r\n\r\n        # Create a JWT payload\r\n        $payload = [Ordered]@{\r\n            'iss' = \"$($EntraAppId)\"\r\n            'sub' = \"$($EntraAppId)\"\r\n            'aud' = \"https://login.microsoftonline.com/$($EntraTenantId)/oauth2/token\"\r\n            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour\r\n            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago\r\n            'iat' = $currentUnixTimestamp\r\n            'jti' = [Guid]::NewGuid().ToString()\r\n        } | ConvertTo-Json\r\n        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')\r\n\r\n        # Extract the private key from the certificate\r\n        $rsaPrivate = $Certificate.PrivateKey\r\n        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()\r\n        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))\r\n\r\n        # Sign the JWT\r\n        $signatureInput = \"$base64Header.$base64Payload\"\r\n        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')\r\n        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')\r\n\r\n        # Create the JWT token\r\n        $jwtToken = \"$($base64Header).$($base64Payload).$($base64Signature)\"\r\n\r\n        $createEntraAccessTokenBody = @{\r\n            grant_type            = 'client_credentials'\r\n            client_id             = $EntraAppId\r\n            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'\r\n            client_assertion      = $jwtToken\r\n            resource              = 'https://graph.microsoft.com'\r\n        }\r\n\r\n        $createEntraAccessTokenSplatParams = @{\r\n            Uri         = \"https://login.microsoftonline.com/$($EntraTenantId)/oauth2/token\"\r\n            Body        = $createEntraAccessTokenBody\r\n            Method      = 'POST'\r\n            ContentType = 'application/x-www-form-urlencoded'\r\n            Verbose     = $false\r\n            ErrorAction = 'Stop'\r\n        }\r\n\r\n        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams\r\n        Write-Output $createEntraAccessTokenResponse.access_token\r\n    }\r\n    catch {\r\n        $PSCmdlet.ThrowTerminatingError($_)\r\n    }\r\n}\r\n\r\n#endregion functions\r\n\r\n\r\n# Active Directory\r\nif ($blnenabled -eq 'true') {\r\n    try {\r\n        try {\r\n            $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }\r\n            Write-Information \"Found AD user [$userPrincipalName]\"\r\n        }\r\n        catch {\r\n            throw \"Could not find AD user [$userPrincipalName]\"\r\n        }\r\n\r\n        $enableUser = Enable-ADAccount -Identity $adUser\r\n    \t\r\n        Write-Information \"Successfully enabled AD user [$userPrincipalName]\"\r\n\r\n        $adUserSID = $([string]$adUser.SID)\r\n        $adUserDisplayName = $adUser.Name\r\n        $Log = @{\r\n            Action            = \"EnableAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"ActiveDirectory\" # optional (free format text) \r\n            Message           = \"Enabled account with username $userPrincipalName\" # required (free format text) \r\n            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $adUserDisplayName # optional (free format text) \r\n            TargetIdentifier  = $adUserSID # optional (free format text) \r\n        }\r\n        #send result back  \r\n        Write-Information -Tags \"Audit\" -MessageData $log\r\n    }\r\n    catch {\r\n        Write-Error \"Could not enable AD user [$userPrincipalName]. Error: $($_.Exception.Message)\"\r\n\r\n        $adUserSID = $([string]$adUser.SID)\r\n        $adUserDisplayName = $adUser.Name\r\n        $Log = @{\r\n            Action            = \"EnableAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"ActiveDirectory\" # optional (free format text) \r\n            Message           = \"Failed to enable account with username $userPrincipalName. Error: $($_.Exception.Message)\" # required (free format text) \r\n            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $adUserDisplayName # optional (free format text) \r\n            TargetIdentifier  = $adUserSID # optional (free format text) \r\n        }\r\n        #send result back  \r\n        Write-Information -Tags \"Audit\" -MessageData $log\r\n    }\r\n}\r\n    \r\nif ($blnenabled -eq 'false') {\r\n    try {\r\n        try {\r\n            $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }\r\n            Write-Information \"Found AD user [$userPrincipalName]\"\r\n        }\r\n        catch {\r\n            throw \"Could not find AD user [$userPrincipalName]\"\r\n        }\r\n\r\n        $disableUser = Disable-ADAccount -Identity $adUser\r\n    \t\r\n        Write-Information \"Successfully disabled AD user [$userPrincipalName]\"\r\n\r\n        $adUserSID = $([string]$adUser.SID)\r\n        $adUserDisplayName = $adUser.Name\r\n        $Log = @{\r\n            Action            = \"DisableAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"ActiveDirectory\" # optional (free format text) \r\n            Message           = \"Disabled account with username $userPrincipalName\" # required (free format text) \r\n            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $adUserDisplayName # optional (free format text) \r\n            TargetIdentifier  = $adUserSID # optional (free format text) \r\n        }\r\n        #send result back\r\n        Write-Information -Tags \"Audit\" -MessageData $log\r\n    }\r\n    catch {\r\n        Write-Error \"Could not disable AD user [$userPrincipalName]. Error: $($_.Exception.Message)\"\r\n\r\n        $adUserSID = $([string]$adUser.SID)\r\n        $adUserDisplayName = $adUser.Name\r\n        $Log = @{\r\n            Action            = \"DisableAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"ActiveDirectory\" # optional (free format text) \r\n            Message           = \"Failed to disable account with username $userPrincipalName. Error: $($_.Exception.Message)\" # required (free format text) \r\n            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $adUserDisplayName # optional (free format text) \r\n            TargetIdentifier  = $adUserSID # optional (free format text) \r\n        }\r\n        #send result back  \r\n        Write-Information -Tags \"Audit\" -MessageData $log\r\n    }\r\n}\r\n\r\n# #######################################\r\n\r\n# # EntraID\r\n\r\n# Setup Connection with Entra/Exo\r\nWrite-Information \"connecting to MS-Entra'\"\r\n$certificate = Get-MSEntraCertificate\r\n$entraToken = Get-MSEntraAccessToken -Certificate $certificate\r\n    \r\n$headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()\r\n$headers.Add('Authorization', \"Bearer $entraToken\")\r\n$headers.Add('Accept', 'application/json')\r\n$headers.Add('Content-Type', 'application/json')\r\n# Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)\r\n$headers.Add('ConsistencyLevel', 'eventual')\r\n\r\nif ($blnenabled -eq 'true') {\r\n    try {\r\n\r\n        # API docs: https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http\r\n        $actionMessage = \"querying account where [UserPrincipalName] = [$($userPrincipalName)]\"\r\n        $getEntraIDAccountSplatParams = @{\r\n            Uri         = \"https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$userPrincipalName'&`$select=$($accountPropertiesToQuery -join ',')\"\r\n            Method      = \"GET\"\r\n            Verbose     = $false\r\n            ErrorAction = \"Stop\"\r\n        }\r\n        Write-Information \"SplatParams: $($getEntraIDAccountSplatParams | ConvertTo-Json)\"\r\n       \r\n        # Add Headers after printing splat\r\n        $getEntraIDAccountSplatParams['Headers'] = $headers\r\n        $getEntraIDAccountResponse = Invoke-RestMethod @getEntraIDAccountSplatParams\r\n        $correlatedAccount = $getEntraIDAccountResponse.Value\r\n        Write-Information \"Queried account where [UserPrincipalName] = [$($userPrincipalName)]. Result: $($correlatedAccount  | ConvertTo-Json)\"\r\n\r\n        #enable entrid account\r\n        try {\r\n            $actionMessage = \"enabling account where [UserPrincipalName] = [$($userPrincipalName)]\"\r\n            $body = @{\r\n                accountEnabled = $true\r\n            }\r\n            $enableEntraIDAccountSplatParams = @{\r\n                Uri         = \"https://graph.microsoft.com/v1.0/users/$($userPrincipalName)\"\r\n                Method      = \"PATCH\"\r\n                body        = $body | ConvertTo-Json\r\n                Verbose     = $false\r\n                ErrorAction = \"Stop\"\r\n            }\r\n            Write-Information \"SplatParams: $($enableEntraIDAccountSplatParams | ConvertTo-Json)\"\r\n\r\n            # Add Headers after printing splat\r\n            $enableEntraIDAccountSplatParams['Headers'] = $headers\r\n            $disableEntraIDAccountResponse = Invoke-RestMethod @enableEntraIDAccountSplatParams\r\n            Write-Information \"Enabled EntraID user [$userPrincipalName]\"\r\n        }\r\n        catch {\r\n            throw \"Could not enable EntraID account [$userPrincipalName]\"\r\n        }  \r\n    \t\r\n        Write-Information \"Successfully enbled EntraID user [$userPrincipalName]\"\r\n\r\n        $Log = @{\r\n            Action            = \"EnableAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"EntraID\" # optional (free format text) \r\n            Message           = \"Enabled account with username $userPrincipalName\" # required (free format text) \r\n            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $userPrincipalName # optional (free format text) \r\n            TargetIdentifier  = $($correlatedAccount.Id) # optional (free format text) \r\n        }\r\n        #send result back\r\n        Write-Information -Tags \"Audit\" -MessageData $log\r\n    }\r\n    catch {\r\n        Write-Error \"Could not disabled and revoked SignInSessions EngtraID user [$userPrincipalName]. Error: $($_.Exception.Message)\"\r\n\r\n        $Log = @{\r\n            Action            = \"EnableAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"EntraID\" # optional (free format text) \r\n            Message           = \"Failed to enable account with username $userPrincipalName. Error: $($_.Exception.Message)\" # required (free format text) \r\n            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $userPrincipalName # optional (free format text) \r\n            TargetIdentifier  = $($correlatedAccount.Id) # optional (free format text) \r\n        }\r\n        #send result back  \r\n        Write-Information -Tags \"Audit\" -MessageData $log\r\n    }\r\n}\r\n    \r\nif ($blnenabled -eq 'false') {\r\n    try {\r\n\r\n        # API docs: https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http\r\n        $actionMessage = \"querying account where [UserPrincipalName] = [$($userPrincipalName)]\"\r\n        $getEntraIDAccountSplatParams = @{\r\n            Uri         = \"https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$userPrincipalName'&`$select=$($accountPropertiesToQuery -join ',')\"\r\n            Method      = \"GET\"\r\n            Verbose     = $false\r\n            ErrorAction = \"Stop\"\r\n        }\r\n        Write-Information \"SplatParams: $($getEntraIDAccountSplatParams | ConvertTo-Json)\"\r\n       \r\n        # Add Headers after printing splat\r\n        $getEntraIDAccountSplatParams['Headers'] = $headers\r\n        $getEntraIDAccountResponse = Invoke-RestMethod @getEntraIDAccountSplatParams\r\n        $correlatedAccount = $getEntraIDAccountResponse.Value\r\n        Write-Information \"Queried account where [UserPrincipalName] = [$($userPrincipalName)]. Result: $($correlatedAccount  | ConvertTo-Json)\"\r\n\r\n        #disable entrid account\r\n        try {\r\n            $actionMessage = \"disabling account where [UserPrincipalName] = [$($userPrincipalName)]\"\r\n            $body = @{\r\n                accountEnabled = $false\r\n            }\r\n            $disableEntraIDAccountSplatParams = @{\r\n                Uri         = \"https://graph.microsoft.com/v1.0/users/$($userPrincipalName)\"\r\n                Method      = \"PATCH\"\r\n                body        = $body | ConvertTo-Json\r\n                Verbose     = $false\r\n                ErrorAction = \"Stop\"\r\n            }\r\n            Write-Information \"SplatParams: $($disableEntraIDAccountSplatParams | ConvertTo-Json)\"\r\n\r\n            # Add Headers after printing splat\r\n            $disableEntraIDAccountSplatParams['Headers'] = $headers\r\n            $disableEntraIDAccountResponse = Invoke-RestMethod @disableEntraIDAccountSplatParams\r\n            Write-Information \"Disabled EntraID user [$userPrincipalName]\"\r\n        }\r\n        catch {\r\n            throw \"Could not disable EntraID account [$userPrincipalName]\"\r\n        }\r\n\r\n        #revoke signin sessions\r\n        try {\r\n            $actionMessage = \"Revoking SignInSessions EntraID account where [UserPrincipalName] = [$($userPrincipalName)]\"\r\n            \r\n            $revokeSignInEntraIDAccountSplatParams = @{\r\n                Uri         = \"https://graph.microsoft.com/v1.0/users/$($userPrincipalName)/revokeSignInSessions\"\r\n                Method      = \"POST\"\r\n                Verbose     = $false\r\n                ErrorAction = \"Stop\"\r\n            }\r\n            Write-Information \"SplatParams: $($revokeSignInEntraIDAccountSplatParams | ConvertTo-Json)\"\r\n\r\n            # Add Headers after printing splat\r\n            $revokeSignInEntraIDAccountSplatParams['Headers'] = $headers\r\n            $disableEntraIDAccountResponse = Invoke-RestMethod @revokeSignInEntraIDAccountSplatParams\r\n            Write-Information \"Revoked SignInSessions EntraID user [$userPrincipalName]\"\r\n        }\r\n        catch {\r\n            throw \"Could not revoke SignInSessions EntraID account [$userPrincipalName]\"\r\n        }    \r\n    \t\r\n        Write-Information \"Successfully disabled and revoked SignInSessions for EntraID user [$userPrincipalName]\"\r\n\r\n        $Log = @{\r\n            Action            = \"DisableAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"EntraID\" # optional (free format text) \r\n            Message           = \"Disabled and revoked SignInSessions account with username $userPrincipalName\" # required (free format text) \r\n            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $userPrincipalName # optional (free format text) \r\n            TargetIdentifier  = $($correlatedAccount.Id) # optional (free format text) \r\n        }\r\n        #send result back\r\n        Write-Information -Tags \"Audit\" -MessageData $log\r\n    }\r\n    catch {\r\n        Write-Error \"Could not disabled and revoked SignInSessions EngtraID user [$userPrincipalName]. Error: $($_.Exception.Message)\"\r\n\r\n        $Log = @{\r\n            Action            = \"DisableAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"EntraID\" # optional (free format text) \r\n            Message           = \"Failed to disable and revoked SignInSessions account with username $userPrincipalName. Error: $($_.Exception.Message)\" # required (free format text) \r\n            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $userPrincipalName # optional (free format text) \r\n            TargetIdentifier  = $($correlatedAccount.Id) # optional (free format text) \r\n        }\r\n        #send result back  \r\n        Write-Information -Tags \"Audit\" -MessageData $log\r\n    }\r\n}","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-unlock" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

