<!-- Description -->
## Description
This HelloID Service Automation Delegated Form provides AD and EntraID account enable / disable functionality. The following options are available:
 1. Search and select the target AD user account
 2. Show basic AD user account attributes of selected target user
 3. Select AD user account attributes for filtering common groupmemberships
 4. Modify the enabled state of selected target AD user account
 5. The selected account will be disabled on AD and EntraID, also the current signed-in sessions will be terminated


## Versioning
| Version | Description | Date |
| - | - | - |
| 1.0.0   | Initial release | 2025/12/11  |


<!-- TABLE OF CONTENTS -->
## Table of Contents
* [Description](#description)
* [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  * [Getting started](#getting-started)
* [Post-setup configuration](#post-setup-configuration)
* [Manual resources](#manual-resources)
* [Getting help](#getting-help)


## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

 _Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_


### Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to setup and run the All-in one Powershell Script in your own environment.

 
## Post-setup configuration
After the all-in-one PowerShell script has run and created all the required resources. The following items need to be configured according to your own environment
 1. Update the following [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)
<table>
  <tr><td><strong>Variable name</strong></td><td><strong>Example value</strong></td><td><strong>Description</strong></td></tr>
  <tr><td>ADusersSearchOU</td><td>[{ "OU": "OU=Disabled Users,OU=HelloID Training,DC=veeken,DC=local"},{ "OU": "OU=Users,OU=HelloID Training,DC=veeken,DC=local"},{"OU": "OU=External,OU=HelloID Training,DC=veeken,DC=local"}]</td><td>Array of Active Directory OUs for scoping AD user accounts in the search result of this form</td></tr>
</table>

## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source 'AD-Entra-user-generate-table-wildcard-deactivate'
This Powershell data source runs an Active Directory query to search for matching AD user accounts. It uses an array of Active Directory OU's specified as HelloID user defined variable named _"ADusersSearchOU"_ to specify the search scope.

### Powershell data source 'AD-Entra-user-generate-table-attributes-basic-deactivate'
This Powershell data source runs an Active Directory query to select a list of basic user attributes of the selected AD user account.  

### Powershell data source 'AD-Entra-user-get-attribute-enabled-deactivate'
This Powershell data source runs an Active Directory query to receive the current enable state of the selected target AD user account.

### Delegated form task 'AD-Entra-user-set-enabled'
This delegated form task will update the enabled state of the selected target AD user account according to the modifications in this form.

## Getting help
_If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/service-automation/506-helloid-sa-active-directory-ad-account-de-activate)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
