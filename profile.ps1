# Azure Functions profile.ps1

# Function to retrieve secrets from Azure Key Vault using Managed Identity
function Get-Secret {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    # Define your Key Vault name and URI
    $KeyVaultName = "RewstPSVault"
    $KeyVaultUri = "https://$KeyVaultName.vault.azure.net/"

    try {
        # Ensure the Az.KeyVault module is installed
        if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) {
            Install-Module -Name Az.KeyVault -Scope CurrentUser -Repository PSGallery -Force
        }
        Import-Module Az.KeyVault -ErrorAction Stop

        # Retrieve the secret using the Az.KeyVault module
        $secret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $Name -AsPlainText -ErrorAction Stop
        return $secret
    }
    catch {
        Write-Error "Failed to retrieve secret '$Name' from Key Vault '$KeyVaultName'. $_"
        throw $_
    }
}

# Ensure the Az module is installed and imported
if (-not (Get-Module -ListAvailable -Name Az)) {
    Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force
}
Import-Module Az -ErrorAction Stop

# Import the ConnectWiseControlAPI module, install if not present
if (-not (Get-Module -ListAvailable -Name ConnectWiseControlAPI)) {
    Install-Module -Name ConnectWiseControlAPI -Scope CurrentUser -Repository PSGallery -Force
}
Import-Module ConnectWiseControlAPI -ErrorAction Stop

# Retrieve ConnectWise credentials from Key Vault
$ConnectWiseUsername = Get-Secret -Name "SCUsername"
$ConnectWisePassword = Get-Secret -Name "SCPassword"

# Convert the password to a secure string
$SecurePassword = ConvertTo-SecureString $ConnectWisePassword -AsPlainText -Force

# Create a PSCredential object
$ConnectWiseCredential = New-Object System.Management.Automation.PSCredential ($ConnectWiseUsername, $SecurePassword)

# Optional: Test the connection to ConnectWise Control
try {
    Connect-CWC -Server "control.domain.com" -Credentials $ConnectWiseCredential -ErrorAction Stop
    Write-Verbose "Successfully connected to ConnectWise Control API."
}
catch {
    Write-Error "Failed to connect to ConnectWise Control API. $_"
    throw $_
}

# Define the URL of the MIT word list
$wordListUrl = "https://www.mit.edu/~ecprice/wordlist.10000"

# Define the local path to cache the word list
$cachePath = "$env:USERPROFILE\.mit_wordlist.txt"

# Function to download and cache the word list
function Get-WordList {
    if (Test-Path -Path $cachePath) {
        Write-Verbose "Using cached word list from $cachePath."
        $wordList = Get-Content -Path $cachePath
    }
    else {
        Write-Verbose "Downloading word list from $wordListUrl..."
        try {
            $response = Invoke-WebRequest -Uri $wordListUrl -UseBasicParsing
            $wordList = $response.Content -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
            # Cache the word list locally for future use
            $wordList | Set-Content -Path $cachePath
            Write-Verbose "Word list downloaded and cached to $cachePath."
        }
        catch {
            Write-Error "Failed to download the word list. Please check your internet connection and the URL."
            exit 1
        }
    }
    return $wordList
}

# Define an array of special characters to choose from
$specialChars = @('!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '?', '/')

# Function to generate a passphrase
function Generate-Passphrase {
    # Get the word list
    $wordList = Get-WordList

    if ($wordList.Count -lt 4) {
        Write-Error "The word list does not contain enough words to generate a passphrase."
        exit 1
    }

    # Select four random words
    $selectedWords = for ($i = 0; $i -lt 4; $i++) {
        $word = Get-Random -InputObject $wordList
        # Capitalize the first letter of each word
        $word = $word.Substring(0,1).ToUpper() + $word.Substring(1)
        $word
    }

    # Concatenate the words without spaces
    $passphrase = ($selectedWords -join '')

    # Generate four random digits
    $numbers = -join ((1..4) | ForEach-Object { Get-Random -Minimum 0 -Maximum 10 })

    # Select a random special character
    $specialChar = Get-Random -InputObject $specialChars

    # Combine all parts
    $fullPassphrase = "$passphrase$numbers$specialChar"

    return $fullPassphrase
}

# Function to create a new ConnectWise user
function New-ConnectWiseUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Email,
        
        [Parameter(Mandatory = $false)]
        [string]$DisplayName = $null,

        [Parameter(Mandatory = $true)]
        [string[]]$SecurityGroups
    )

    if (-not $DisplayName) {
        $DisplayName = $Email.Split('@')[0]
    }

    # Generate a passphrase
    $generatedPassphrase = Generate-Passphrase

    # Create credential object for new user
    $SecurePassword = ConvertTo-SecureString "$generatedPassphrase" -AsPlainText -Force
    $NewUserCreds = New-Object System.Management.Automation.PSCredential ("$Email", $SecurePassword)

    # Generate a new MFA token
    try {
        $MFA = New-CWCMFA -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to generate MFA token for new user '$Email'. $_"
        throw $_
    }

    # Define the new user properties
    $NewUser = @{
        Credentials    = $NewUserCreds
        Email          = $Email
        DisplayName    = $DisplayName
        OTP            = $MFA.OTP
        SecurityGroups = $SecurityGroups
    }

    # Create the new user
    try {
        New-CWCUser @NewUser -Verbose
        Write-Verbose "New user '$Email' created successfully with MFA enabled."
    }
    catch {
        Write-Error "Failed to create new user '$Email'. $_"
        throw $_
    }

    # Prepare the output object
    $output = @{
        UserName = $Email
        Password = $generatedPassphrase
        OTP      = $MFA.OTP
    }

    # Convert the output to JSON and output it
    $outputJson = $output | ConvertTo-JSON -Compress
    Write-Output $outputJson
}

# Export the function to make it available outside the profile script
Export-ModuleMember -Function New-ConnectWiseUser, Get-Secret
