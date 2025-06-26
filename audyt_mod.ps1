param (
    [string]$target = (Get-Location).Path,
    [string]$resultpath = '.\result.csv',
    $AD = $False
)

$ErrorActionPreference = 'SilentlyContinue'
Import-Module ActiveDirectory

# Function: List all files and folders and get ACLs
function Get-Files {
    param ([string]$path)
    $files = Get-ChildItem -Path $path -Recurse -Force | Get-Acl
    return $files
}

# Function: Get ACLs from Active Directory OUs
function Get-ADACLs {
    $ad = Get-ADOrganizationalUnit -Filter 'Name -like "*"'
    $result = @()
    foreach ($a in $ad) {
        $result += Get-Acl -Path ("AD:" + $a.DistinguishedName)
    }
    return $result
}

# Function: Convert ACLs into a flat list of entries
function Gather-Acls {
    param ($aclset)
    $acls = @()
    foreach ($a in $aclset) {
        if ($a -and $a.Access) {
            foreach ($acl in $a.Access) {
                if (
                    !$acl.IsInherited -and
                    $acl.IdentityReference -notlike "BUILTIN*" -and
                    $acl.IdentityReference -notlike "NT AUTHORITY*" -and
                    $acl.IdentityReference -notlike "*DZANIE NT*"
                ) {
                    $rights = $acl.FileSystemRights + $acl.ActiveDirectoryRights
                    $path = $a.Path
                    if ($path.Contains("::")) {
                        $path = $path.Substring($path.IndexOf("::") + 2)
                    }
                    $acls += [PSCustomObject]@{
                        IdentityReference = $acl.IdentityReference
                        Path              = $path
                        AccessType        = $acl.AccessControlType
                        Rights            = $rights
                    }
                }
            }
        }
    }
    return $acls
}

# Function: Map identities to AD object types
function Gather-Objects {
    param ($acls)
    $unique = $acls.IdentityReference | Sort-Object | Get-Unique
    $result = @{}

    foreach ($u in $unique) {
        $id = $u.ToString()
        if ($id -match "^S-\d+-\d+-\d+-\d+") {
            $result[$id] = "Orphaned"
        }
        else {
            $name = $id.Split('\')[-1]
            try {
                $o_type = (Get-ADObject -Filter "sAMAccountName -eq '$name'").ObjectClass
            } catch {
                $o_type = "Unknown"
            }
            $result[$id] = $o_type
        }
    }

    return $result
}

# Function: Create final report object
function Create-Report {
    param ($acls, $obj)
    $result = @()

    foreach ($a in $acls) {
        $identity = $a.IdentityReference.ToString()
        $otype = if ($obj.ContainsKey($identity)) { $obj[$identity] } else { "Unknown" }

        $result += [PSCustomObject]@{
            IdentityReference = $a.IdentityReference
            ObjectType        = $otype
            Path              = $a.Path
            AccessType        = $a.AccessType
            Rights            = $a.Rights
        }
    }

    return $result
}

# Main execution logic
"Skrypt zaczął pracę o " + Get-Date >> .\log.txt 
if ($AD) {
    $acls_file = Get-ADACLs
} else {
    $acls_file = Get-Files -path $target
}

Write-Host "ACLs collected: $($acls_file.Count)"

$acls = Gather-Acls $acls_file
Write-Host "Filtered ACL entries: $($acls.Count)"

$ad_objects = Gather-Objects $acls
Write-Host "Unique identities mapped: $($ad_objects.Count)"

$final_result = Create-Report -acls $acls -obj $ad_objects
if($resultpath -eq '.\result.csv'){$resultpath = ".\result_"+$target.split('\')[-1]+"_"+(Get-date).Toshortdatestring()+".csv"}
$final_result | Export-Csv -Path $resultpath -UseCulture -NoTypeInformation
"Skrypt zakończył pracę o " + Get-Date >> .\log.txt
