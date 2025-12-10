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
