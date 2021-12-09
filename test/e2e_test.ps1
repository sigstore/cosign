# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

function New-TmpDir {
    $parent = [System.IO.Path]::GetTempPath()
    $name = [System.IO.Path]::GetRandomFileName()
    New-Item -ItemType Directory -Path (Join-Path $parent $name)
}

make cosign
$TmpDir = New-TmpDir
Copy-Item -Path .\cosign -Destination (Join-Path $TmpDir cosign.exe)
# Copy-Item -Path (Join-Path $pwd sget.exe) -Destination (Join-Path $TmpDir sget.exe)

Push-Location $TmpDir

# See if things blow up immediately
.\cosign.exe version

# Generate a random alphanumeric password for the private key
$pass = -join (((48..57)+(65..90)+(97..122)) * 80 | Get-Random -Count 10 | %{[char]$_})
# $Env:COSIGN_PASSWORD = $pass

Write-Output $pass | .\cosign.exe generate-key-pair
$signing_key = "cosign.key"
$verification_key = "cosign.pub"

$test_img = "gcr.io/distroless/static"
Write-Output $pass | .\cosign.exe sign --key $signing_key --output-signature interactive.sig $test_img
.\cosign.exe verify --key $verification_key --signature interactive.sig $test_img

Pop-Location

Write-Output "Success"
