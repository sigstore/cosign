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

Push-Location $TmpDir

# See if things blow up immediately
.\cosign.exe version

# Generate a random alphanumeric password for the private key
$pass = Get-Random

Write-Output $pass | .\cosign.exe generate-key-pair
$signing_key = "cosign.key"
$verification_key = "cosign.pub"

Write-Output "hello world" | Out-File -FilePath "hello_world.txt"
Write-Output $pass | .\cosign.exe sign-blob --key $signing_key --bundle test.sigstore.json --use-signing-config=false --tlog-upload=false hello_world.txt
.\cosign.exe verify-blob --key $verification_key --bundle test.sigstore.json --insecure-ignore-tlog=true hello_world.txt

Pop-Location

Write-Output "Success"
