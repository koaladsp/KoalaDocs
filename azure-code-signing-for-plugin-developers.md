# Azure Code Signing for plugin developers

🌠 Latest update: Mar 10, 2024.

This guide covers the steps necessary to set up a modern code signing flow using Azure Code Signing on Microsoft Windows, for example as part of a automated build or CI process. It is primarily meant for developers that are working on audio plugins and apps and covers a few specifics on things such as AAX code signing, with the hope that it will be useful for some.

Azure Code Signing is a new all-in-one code signing service for Microsoft Azure which, at the time of writing, is still in a closed preview phase but expected to launch somewhere in 2024 to the general public. We recommend this service because it is provided by Microsoft itself and as such all tools come directly from Microsoft, removing the need for any third party tools to make code signing work. All in all, our experience with it has been very good.

We would like to share this guidelines, so any developers can already make preparations to migrate to this service in due time, or perhaps already have a go if they have already been enrolled in the Azure preview program and have access to ACS today.

## 1. Current state of affairs

Since 2022, code signing certificates (EV) for Microsoft Windows are no longer allowed to be derived from "unprotected" private key files. Private keys must be generated securely in a Hardware Security Module (HSM) with FIPS 140-2 or EAL 4+ rating, and thus a HSM is now a necessity for plain old local code signing.

Normally one would use `signtool.exe` with a local private key file beloning to a public-private certificate keypair issued by one of the allowed authorities, but this no longer works without use of a local HSM such as a Yubikey dongle. This can complicate things because you now need either a local HSM, a dedicated shared HSM or remote HSM.

Fortunately, there are currently at least two viable alternatives out there that will be covered in this guide.

1. Azure Code Signing - a new Azure service aimed specifically at code signing, which we can recommend.
2. Azure Key Vault - an Azure service that provides a remote HSM.

We will cover the use of Azure Code Signing in this guide.

## 2. Azure Code Signing (ACS)

The way Azure Code Signing works is by extending `signtool.exe`. This is a known tool for code signing which is included in the Windows SDK. The connection to Azure is used to create and use an ad hoc certificate which is then used to sign a binary. 

These certificates are issued by Microsoft. In fact, Microsoft itself acts as a certificate authority with a root certificate chain already preinstalled in modern versions of Microsoft Windows.

Unlike certificates issued from authorities such as Sectigo, DigiCert and others, the certificates issued by ACS are only valid for a short time (e.g. several days) so that certificates cannot be stolen easily. To be fair, the new requirement for a HSM to store these certificates, instead of a file, also makes this much less likely but still.

In any case, `signtool.exe` automatically and transparently takes care of issuing a new certificates when necessary. In this sense, it is very common to modern non-profit certificate authorities such as [Let's Encrypt](https://letsencrypt.com).

### 2.1. Pricing

The pricing plan of Azure Code Signing is currently unknown and it is expected that this will be revealed somewhere in 2024. We expect the pricing to be reasonable, as it concerns a fundamental service for many Microsoft Windows developers.

### 2.2. Setting up ACS on Microsoft Azure

The following assumes that you have access to the Azure Code Signing service in your Microsoft Azure account. These steps will involve using the Microsoft Azure web portal to configure things. It will only be necessary to configure these things once, and you should be good to go afterwards.

#### 2.2.1. Creating an ACS resource

First, create an ACS resource:

* Go to [Code Signing Accounts](https://portal.azure.com/?feature.customportal=false&Microsoft_Azure_CodeSigning_assettypeoptions=%7B%22CodeSigningAccounts%22%3A%7B%22options%22%3A%22%22%7D%7D&microsoft_azure_codesigning=true#view/HubsExtension/BrowseResource/resourceType/Microsoft.CodeSigning%2Fcodesigningaccounts)
* Click "Create". Fill in the details, pick one of the following regions:
	* East US (https://eus.codesigning.azure.net)
	* West US (https://wus.codesigning.azure.net)
	* West Central US (https://wcus.codesigning.azure.net)
	* West US 2 (https://wus2.codesigning.azure.net)
	* North Europe (https://neu.codesigning.azure.net)  
	* West Europe (https://weu.codesigning.azure.net)

#### 2.2.2. Granting administrative access

Now that we have an ACS resource, we need to grant administrative access in order to access it:

* Open the Code Signing resource.
* Go to "Access control (IAM)" (left menu).
* Click "Add" and "Add role assignment" (top).
* Select "Code Signing Identity Verifier". Next.
* Type in and select your current user account.
* Keep clicking "Review + assign" until done.

#### 2.2.3. Create a code signing app

We will now create a code signing app, which we will be able to use with any of our local code signing tools:

* In the Azure portal, search for Microsoft Entra ID (formerly: Azure Active Directory).
* Click "Add" and "App registration" (top).
* Name: codesigning-app (or anything else)
* Who can use this application or access this API?: Accounts in this organizational directory only (Default Directory only - Single tenant)
* Redirect URI: (leave as is)
* Click "Create".
* Click on the app resource you've just created.
* Note down the "Application (client) ID" for later usage.
* Go to "Certificates & secrets" (left menu).
* Click "Client secrets" (top).
* Click "New client secret".
* Set "Expires" to the highest date possible.
* Click "Add".
* Note down the "Value", this is the secret for later usage.

#### 2.2.4. Granting code signing app permissions

We will now grant our code signing app the right permissions:

* Open the Code Signing resource.
* Go to "Access control (IAM)" (left menu).
* Click "Add" and "Add role assignment" (top).
* Select "Code Signing Certificate Profile Signer". Next.
* Type in and select your app name (e.g. codesigning-app).
* Keep clicking "Review + assign" until done.

#### 2.2.5. Verify identity

Now that the ACS basics have been set up, we need to set up ACS so we can issue certificates. One requirements for that is that your personal or company identity has been validated with Microsoft Azure.
Let's start that process:

* Open the Code Signing resource.
* Go to "Identity validation" (left menu).
* Click "New" and "Public Trust" (top).
* Fill in the details. Note that Primary and Secondary E-mail(s) will not be published in any certificate.

Your mileage may vary, but expect this to take at least a day to complete as it is a one-time verification that concerns your Microsoft Azure account.

#### 2.2.6. Create certificate profile

We now need to create a certificate profile, which we can use for code signing:

* Open the Code Signing resource.
* Go to "Certificate profiles" (left menu).
* Click "Create" and "Public Trust" (top).
* Fill in a name and select the "Verified CN and O" appropriately (will appear when the identity validation process is done).
* Click "Create".

The certificate should now be ready to be used with signing.

Luckely, our setup on Microsoft Azure should now be complete.

## 2.3. Setting up ACS for code signing

Now that ACS has been configured on Microsoft Azure, we can set up the code signing tools on our local development or automated build machine.
The following steps assume that you have access to a machine running a recent version of Microsoft Windows, and you are able to execute commands in the command prompt.

#### 2.3.1. Preparing the Azure CLI

To start off, we will install the Microsoft Azure CLI which will allow access from the machine to Azure.

* Install the [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-cli).

We now need to create a "service principal" locally to enable our code signing tools to work. The following steps have been supplied to us and seem to work fine:

* Log in with the CLI using your admin/owner account:
	```dos
	az login
	```
* Execute the following manual commands using the CLI
	```dos
	az ad sp create --id cf2ab426-f71a-4b61-bb8a-9e505b85bc2e
	az ad app permission grant --id cf2ab426-f71a-4b61-bb8a-9e505b85bc2e --api 00000003-0000-0000-c000-000000000000 --scope User.Read
	```

### 2.3.2. Preparing `signtool.exe`

`signtool.exe` is the known code signing tools distributed by Microsoft with Windows SDKs. It can be used with ACS, which is excellent since it means that it is directly supported by Microsoft itself. In order to make it work however, it needs to be extended by means of a Dlib file.

Make sure that you have installed the minimum required dependencies:

* Windows 10 SDK 10.0.19041 or higher (or Windows 11 SDK). This includes the minimum required version of `signtool.exe`.
* [.NET 6.0 runtime](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-6.0.9-windows-x64-installer). If this is not installed, signtool will fail silently without output.

---

Download the Azure Code Signing Dlib for signtool. It should have been provided by Microsoft either as part of a quick start guide, or it will be provided as soon as ACS enters public use.
Note that it should be extracted to a specific directory mentioned in the instructions.
We will replace this with the appropriate public links as soon as ACS is available for public use.

---

After setting up the Dlib, we need to create a metadata configuration JSON file inside the Dlib's installation directory:

* Create a `metadata.json` file with the following contents (replace details accordingly):
	```
	{
		"Endpoint": "<Code Signing Account Endpoint>", 
		"CodeSigningAccountName": "<Code Signing Account Name>", 
		"CertificateProfileName": "<Certificate Profile Name>", 
		"CorrelationId": "<Optional CorrelationId*>" 
	} 
	```
	* Endpoint: choose according to the endpoint you've chosen for the Azure Code Signing:
		* East US (https://eus.codesigning.azure.net)
		* West US (https://wus.codesigning.azure.net)
		* West Central US (https://wcus.codesigning.azure.net)
		* West US 2 (https://wus2.codesigning.azure.net)
		* North Europe (https://neu.codesigning.azure.net)  
		* West Europe (https://weu.codesigning.azure.net)
	* CorrelationId: an optional string to identify these requests, not really necessary.

To help along with the configuration of the signtool, especially for automated build systems, we will also add some environment variables to the system. Note that these environment variables are not necessary, but if you choose not to use them, replace the use of them in any of the commands elsewhere in this guide.

* Make sure the following environment variables are set accordingly to use with the code signing app you've created earlier (e.g. codesigning-app):
	* `AZURE_TENANT_ID`: The Microsoft Entra tenant (directory) ID. Can be found in Microsoft Entra ID.
	* `AZURE_CLIENT_ID`: The client (application) ID of an App Registration in the tenant.
	* `AZURE_CLIENT_SECRET`: A client secret ("value") that was generated for the App Registration.
* Create an environment variable `ACS_DLIB` that points to the exact path of the `Azure.CodeSigning.Dlib.dll` in the archive that was extracted above.
* Create an environment variable `ACS_JSON` that points to the exact path of the `metadata.json` file that was created above.

### 2.3.3. Testing `signtool.exe`

We will now make sure that `signtool.exe` is working and capable of using ACS to sign executables.

Make sure that you have installed the minimum required dependencies:

* Windows 10 SDK 10.0.19041 or higher (or Windows 11 SDK). This includes the minimum required version of `signtool.exe`.
* [.NET 6.0 runtime](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-6.0.9-windows-x64-installer). If this is not installed, signtool will fail silently without output.

`signtool.exe` can typically be found at a location such as: `C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64`.

You should now be able to execute signtool accordingly:

```
signtool.exe sign /v /debug /fd SHA256 /tr "http://timestamp.acs.microsoft.com" /td SHA256 /dlib %ACS_DLIB% /dmdf %ACS_JSON% filetobesigned.exe
```

### 2.3.4. Using `signtool.exe` with AAX `wraptool.exe`

Since PACE Eden SDK's wraptool utility uses signtool.exe as well, and ProTools on Windows expects .aax plugins to be signed with a whitelisted Microsoft certificate authority, wraptool needs to be adjusted in order to use the Azure Code Signing as well.

Normally wraptool relies on either a certificate file and password (no longer possible due to HSM) or a sign id (HSM), with no apparent support for any other tools or options. Luckely wraptool just simply runs signtool with a bunch of arguments and the signtool location can even be specified. We use a signtool wrapper instead that injects all the necessary arguments, and this seems to work.

This section presents a stop-gap workaround while wraptools remains incompatible. It is by no means ideal but it works.

* Make sure you have installed Python 3 as the batch file below relies on its use.
* Choose a directory on the system that is accessible and where you can place the wrappers for use with `wraptool.exe`.

Now proceed by creating the wrapper files:

* Create a python file called `aax-signtool.py` with the following contents in a directory of your choice:
	```python
	import sys
	import re
	
	# args.tmp should contain untouched CLI arguments
	args = None
	with open('args.tmp', 'r') as f:
		args = f.read()
	
	if args:
		with open('args.tmp', 'w') as f:
			# Filter and keep anything that starts with a C:\ path, discard any optional quotes and write back to file
			match = re.search(r'\"?(c\:\\.*?)\"?$', args, re.IGNORECASE)
			if match and match[1]:
				f.write(match[1])
				exit(0)
	
	# Nothing to be done
	exit(1)
	```

* Create a batch file called `aax-signtool.bat` with the following contents in a directory of your choice:
	```dos
	@echo off
	
	:: KDSP Signtool wrapper for Eden SDK / AAX wraptool
	::
	:: wraptool invokes signtool but makes a lot of assumptions about how we're going to sign
	:: which are incompatible with Azure Code Signing.
	::
	:: This tool removes all its arguments and replaces it with the correct or necessary ones.
	:: Please adjust accordingly if necessary.
	::
	:: Run Eden SDK's wraptool as follows:
	::
	:: wraptool.exe sign --signtool signtool.bat --signid 1 --verbose --installedbinaries --account ... --password ... --wcguid ... --in ...
	::
	:: signid 1 is bogus, but wraptool needs this nonsense in order to start up..
	::
	:: The following environment variables are necessary:
	::
	:: SIGNTOOL_PATH
	:: ACS_DLIB (points to Dlib.dll file)
	:: ACS_JSON (points to the metadata.json file)
	:: AZURE_TENANT_ID (Microsoft Azure tenant ID)
	:: AZURE_CLIENT_ID (Microsoft Azure codesigning app client ID)
	:: AZURE_SECRET_ID (Microsoft Azure codesigning app secret value)
	::
	
	:: Get script root dir, so we can find aax-signtool.py
	set root=%~dp0
	set root=%root:~0,-1%
	
	:: wraptool seems to mangle signtool's args and doesn't properly quote-escape the final binary path,
	:: and batch is not easy with string handling, so we use python to fix things up..
	set args=%*
	echo %args%>args.tmp
	echo Patched signtool: Input arguments: %args%
	python %root%\aax-signtool.py
	set /p args=<args.tmp
	echo Patched signtool: Filtered arguments: %args%
	set file="%args%"
	
	echo Patched signtool: File to sign: %file%
	
	if not defined SIGNTOOL_PATH (
		echo Patched signtool: ERROR: SIGNTOOL_PATH not defined
		exit /b 1000
	)
	if not exist "%SIGNTOOL_PATH%" (
		echo Patched signtool: ERROR: Could not find signtool.exe at "%SIGNTOOL_PATH%"
		exit /b 1000
	)
	
	echo Patched signtool: Executing: "%SIGNTOOL_PATH%" sign /v /debug /fd SHA256 /tr "http://timestamp.acs.microsoft.com" /td SHA256 /dlib %ACS_DLIB% /dmdf %ACS_JSON% %file%
	"%SIGNTOOL_PATH%" sign /v /debug /fd SHA256 /tr "http://timestamp.acs.microsoft.com" /td SHA256 /dlib %ACS_DLIB% /dmdf %ACS_JSON% %file%
	@if %errorlevel% neq 0 exit /b %errorlevel%
	
	echo Patched signtool: Success
	```

You should now be able to run `wraptool.exe` such that it invokes `signtool.exe`, making use of ACS. In order to this, you will need to pass the following arguments, e.g.:

```dos
wraptool.exe sign --signtool aax-signtool.bat --signid 1 --verbose --installedbinaries --account ... --password ... --wcguid ... --in ...
```

Where `aax-signtool.bat` should point its absolute path inside your chosen directory, such as `C:\Tools\aax-signtools.bat`.
You can ignore the `--signid 1` argument, but it is necessary to make wraptool work.

You should now be set up to code sign AAX using ACS.

## 3. Final words

With any luck, you should now have Azure Code Signing working with `signtool.exe` to sign application binaries, as well as with `wraptool.exe` to sign AAX binaries.

Happy hacking!

🐨🚀
