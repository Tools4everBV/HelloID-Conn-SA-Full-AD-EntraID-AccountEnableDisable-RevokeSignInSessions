$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$userPrincipalName = $form.gridUsers.UserPrincipalName
$blnenabled = $form.enabled
$accountPropertiesToQuery = @("id")

#region functions
function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($EntraBase64)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $EntraCertPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        # Get the DER encoded bytes of the certificate
        $derBytes = $Certificate.RawData

        # Compute the SHA-256 hash of the DER encoded bytes
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Create a JWT (JSON Web Token) header
        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        # Calculate the Unix timestamp (seconds since 1970-01-01T00:00:00Z) for 'exp', 'nbf' and 'iat'
        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        # Create a JWT payload
        $payload = [Ordered]@{
            'iss' = "$($EntraAppId)"
            'sub' = "$($EntraAppId)"
            'aud' = "https://login.microsoftonline.com/$($EntraTenantId)/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour
            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Extract the private key from the certificate
        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        # Sign the JWT
        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Create the JWT token
        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $EntraAppId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$($EntraTenantId)/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion functions


# Active Directory
if ($blnenabled -eq 'true') {
    try {
        try {
            $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }
            Write-Information "Found AD user [$userPrincipalName]"
        }
        catch {
            throw "Could not find AD user [$userPrincipalName]"
        }

        $enableUser = Enable-ADAccount -Identity $adUser
    	
        Write-Information "Successfully enabled AD user [$userPrincipalName]"

        $adUserSID = $([string]$adUser.SID)
        $adUserDisplayName = $adUser.Name
        $Log = @{
            Action            = "EnableAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Enabled account with username $userPrincipalName" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $adUserDisplayName # optional (free format text) 
            TargetIdentifier  = $adUserSID # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
    catch {
        Write-Error "Could not enable AD user [$userPrincipalName]. Error: $($_.Exception.Message)"

        $adUserSID = $([string]$adUser.SID)
        $adUserDisplayName = $adUser.Name
        $Log = @{
            Action            = "EnableAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Failed to enable account with username $userPrincipalName. Error: $($_.Exception.Message)" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $adUserDisplayName # optional (free format text) 
            TargetIdentifier  = $adUserSID # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
}
    
if ($blnenabled -eq 'false') {
    try {
        try {
            $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }
            Write-Information "Found AD user [$userPrincipalName]"
        }
        catch {
            throw "Could not find AD user [$userPrincipalName]"
        }

        $disableUser = Disable-ADAccount -Identity $adUser
    	
        Write-Information "Successfully disabled AD user [$userPrincipalName]"

        $adUserSID = $([string]$adUser.SID)
        $adUserDisplayName = $adUser.Name
        $Log = @{
            Action            = "DisableAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Disabled account with username $userPrincipalName" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $adUserDisplayName # optional (free format text) 
            TargetIdentifier  = $adUserSID # optional (free format text) 
        }
        #send result back
        Write-Information -Tags "Audit" -MessageData $log
    }
    catch {
        Write-Error "Could not disable AD user [$userPrincipalName]. Error: $($_.Exception.Message)"

        $adUserSID = $([string]$adUser.SID)
        $adUserDisplayName = $adUser.Name
        $Log = @{
            Action            = "DisableAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Failed to disable account with username $userPrincipalName. Error: $($_.Exception.Message)" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $adUserDisplayName # optional (free format text) 
            TargetIdentifier  = $adUserSID # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
}

# #######################################

# # EntraID

# Setup Connection with Entra/Exo
Write-Information "connecting to MS-Entra'"
$certificate = Get-MSEntraCertificate
$entraToken = Get-MSEntraAccessToken -Certificate $certificate
    
$headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
$headers.Add('Authorization', "Bearer $entraToken")
$headers.Add('Accept', 'application/json')
$headers.Add('Content-Type', 'application/json')
# Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
$headers.Add('ConsistencyLevel', 'eventual')

if ($blnenabled -eq 'true') {
    try {

        # API docs: https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http
        $actionMessage = "querying account where [UserPrincipalName] = [$($userPrincipalName)]"
        $getEntraIDAccountSplatParams = @{
            Uri         = "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$userPrincipalName'&`$select=$($accountPropertiesToQuery -join ',')"
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        Write-Information "SplatParams: $($getEntraIDAccountSplatParams | ConvertTo-Json)"
       
        # Add Headers after printing splat
        $getEntraIDAccountSplatParams['Headers'] = $headers
        $getEntraIDAccountResponse = Invoke-RestMethod @getEntraIDAccountSplatParams
        $correlatedAccount = $getEntraIDAccountResponse.Value
        Write-Information "Queried account where [UserPrincipalName] = [$($userPrincipalName)]. Result: $($correlatedAccount  | ConvertTo-Json)"

        #enable entrid account
        try {
            $actionMessage = "enabling account where [UserPrincipalName] = [$($userPrincipalName)]"
            $body = @{
                accountEnabled = $true
            }
            $enableEntraIDAccountSplatParams = @{
                Uri         = "https://graph.microsoft.com/v1.0/users/$($userPrincipalName)"
                Method      = "PATCH"
                body        = $body | ConvertTo-Json
                Verbose     = $false
                ErrorAction = "Stop"
            }
            Write-Information "SplatParams: $($enableEntraIDAccountSplatParams | ConvertTo-Json)"

            # Add Headers after printing splat
            $enableEntraIDAccountSplatParams['Headers'] = $headers
            $disableEntraIDAccountResponse = Invoke-RestMethod @enableEntraIDAccountSplatParams
            Write-Information "Enabled EntraID user [$userPrincipalName]"
        }
        catch {
            throw "Could not enable EntraID account [$userPrincipalName]"
        }  
    	
        Write-Information "Successfully enbled EntraID user [$userPrincipalName]"

        $Log = @{
            Action            = "EnableAccount" # optional. ENUM (undefined = default) 
            System            = "EntraID" # optional (free format text) 
            Message           = "Enabled account with username $userPrincipalName" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $userPrincipalName # optional (free format text) 
            TargetIdentifier  = $($correlatedAccount.Id) # optional (free format text) 
        }
        #send result back
        Write-Information -Tags "Audit" -MessageData $log
    }
    catch {
        Write-Error "Could not disabled and revoked SignInSessions EngtraID user [$userPrincipalName]. Error: $($_.Exception.Message)"

        $Log = @{
            Action            = "EnableAccount" # optional. ENUM (undefined = default) 
            System            = "EntraID" # optional (free format text) 
            Message           = "Failed to enable account with username $userPrincipalName. Error: $($_.Exception.Message)" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $userPrincipalName # optional (free format text) 
            TargetIdentifier  = $($correlatedAccount.Id) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
}
    
if ($blnenabled -eq 'false') {
    try {

        # API docs: https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http
        $actionMessage = "querying account where [UserPrincipalName] = [$($userPrincipalName)]"
        $getEntraIDAccountSplatParams = @{
            Uri         = "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$userPrincipalName'&`$select=$($accountPropertiesToQuery -join ',')"
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        Write-Information "SplatParams: $($getEntraIDAccountSplatParams | ConvertTo-Json)"
       
        # Add Headers after printing splat
        $getEntraIDAccountSplatParams['Headers'] = $headers
        $getEntraIDAccountResponse = Invoke-RestMethod @getEntraIDAccountSplatParams
        $correlatedAccount = $getEntraIDAccountResponse.Value
        Write-Information "Queried account where [UserPrincipalName] = [$($userPrincipalName)]. Result: $($correlatedAccount  | ConvertTo-Json)"

        #disable entrid account
        try {
            $actionMessage = "disabling account where [UserPrincipalName] = [$($userPrincipalName)]"
            $body = @{
                accountEnabled = $false
            }
            $disableEntraIDAccountSplatParams = @{
                Uri         = "https://graph.microsoft.com/v1.0/users/$($userPrincipalName)"
                Method      = "PATCH"
                body        = $body | ConvertTo-Json
                Verbose     = $false
                ErrorAction = "Stop"
            }
            Write-Information "SplatParams: $($disableEntraIDAccountSplatParams | ConvertTo-Json)"

            # Add Headers after printing splat
            $disableEntraIDAccountSplatParams['Headers'] = $headers
            $disableEntraIDAccountResponse = Invoke-RestMethod @disableEntraIDAccountSplatParams
            Write-Information "Disabled EntraID user [$userPrincipalName]"
        }
        catch {
            throw "Could not disable EntraID account [$userPrincipalName]"
        }

        #revoke signin sessions
        try {
            $actionMessage = "Revoking SignInSessions EntraID account where [UserPrincipalName] = [$($userPrincipalName)]"
            
            $revokeSignInEntraIDAccountSplatParams = @{
                Uri         = "https://graph.microsoft.com/v1.0/users/$($userPrincipalName)/revokeSignInSessions"
                Method      = "POST"
                Verbose     = $false
                ErrorAction = "Stop"
            }
            Write-Information "SplatParams: $($revokeSignInEntraIDAccountSplatParams | ConvertTo-Json)"

            # Add Headers after printing splat
            $revokeSignInEntraIDAccountSplatParams['Headers'] = $headers
            $disableEntraIDAccountResponse = Invoke-RestMethod @revokeSignInEntraIDAccountSplatParams
            Write-Information "Revoked SignInSessions EntraID user [$userPrincipalName]"
        }
        catch {
            throw "Could not revoke SignInSessions EntraID account [$userPrincipalName]"
        }    
    	
        Write-Information "Successfully disabled and revoked SignInSessions for EntraID user [$userPrincipalName]"

        $Log = @{
            Action            = "DisableAccount" # optional. ENUM (undefined = default) 
            System            = "EntraID" # optional (free format text) 
            Message           = "Disabled and revoked SignInSessions account with username $userPrincipalName" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $userPrincipalName # optional (free format text) 
            TargetIdentifier  = $($correlatedAccount.Id) # optional (free format text) 
        }
        #send result back
        Write-Information -Tags "Audit" -MessageData $log
    }
    catch {
        Write-Error "Could not disabled and revoked SignInSessions EngtraID user [$userPrincipalName]. Error: $($_.Exception.Message)"

        $Log = @{
            Action            = "DisableAccount" # optional. ENUM (undefined = default) 
            System            = "EntraID" # optional (free format text) 
            Message           = "Failed to disable and revoked SignInSessions account with username $userPrincipalName. Error: $($_.Exception.Message)" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $userPrincipalName # optional (free format text) 
            TargetIdentifier  = $($correlatedAccount.Id) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
}
