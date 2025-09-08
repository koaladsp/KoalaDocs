# Azure Trusted Signing for plugin developers

🌠 Latest update: Sep 8, 2025 by [Cecill Etheredge](https://github.com/ijsf).

This guide covers the steps necessary to set up a modern code signing flow using Azure Trusted Signing on Microsoft Windows, for example as part of a automated build or CI process. It is primarily meant for developers that are working on audio plugins and apps and covers a few specifics on things such as AAX code signing, PACE wrapped binaries, with the hope that it will be useful for some.

[Azure Trusted Signing](https://azure.microsoft.com/en-us/products/trusted-signing) is a new end-to-end code signing service which is currently available to the general public as part of Microsoft Azure.

We recommend this service because it is provided by Microsoft itself and as such all tools come directly from Microsoft, removing the need for any third party tools to make code signing work, or for any hardware-backed certificate setups. All in all, our experience with it has been very good.

## 1. Current state of affairs

Since 2022, code signing certificates (EV) for Microsoft Windows are no longer allowed to be derived from "unprotected" private key files. Private keys must be generated securely in a Hardware Security Module (HSM) with FIPS 140-2 or EAL 4+ rating, and thus a HSM is now a necessity for plain old local code signing.

Normally one would use `signtool.exe` with a local private key file belonging to a public-private certificate keypair issued by one of the allowed authorities, but this no longer works without use of a local HSM such as a Yubikey dongle. This can complicate things because you now need either a local HSM, a dedicated shared HSM or remote HSM.

Fortunately, there are currently at least two viable alternatives out there that will be covered in this guide.

1. Azure Trusted Signing - a new Azure service aimed specifically at code signing, which we can recommend.
2. Azure Key Vault - an Azure service that provides a remote HSM.

As the Azure Key Vault is a replacement for HSM use cases, will cover the use of the much easier Azure Trusted Signing in this guide instead.

## 2. Azure Trusted Signing

⚠ Please note that there are currently at least two ways of using Azure Trusted Signing:

1. The **_official_** `signtool.exe` and its [Trusted Signing Dlib extension](https://learn.microsoft.com/en-us/azure/trusted-signing/how-to-signing-integrations) as supported by Microsoft.
2. The **_unofficial_** [AzureSignTool](https://github.com/vcsjones/AzureSignTool), a separate handy tool not maintained by Microsoft.

This guide focuses on using the _official Microsoft signtool_ because of the long-term support benefits, though the _unofficial AzureSignTool_ (2) may just as well be a viable option for you.

The way the official Trusted Signing tool works is by extending the existing Microsoft supplied `signtool.exe` with a dynamic library for Azure support. The connection to Azure is used to create and use an ad hoc certificate which is then used to sign a binary. These certificates are issued by Microsoft. In fact, Microsoft itself acts as a certificate authority with a root certificate chain already preinstalled in modern versions of Microsoft Windows.

Unlike certificates issued from authorities such as Sectigo, DigiCert and others, the certificates issued by Azure Trusted Signing are only valid for a short time (e.g. several days) so that leaked certificates cannot be abused easily by malicious actors. To be fair, the new requirement for a HSM to store these certificates, instead of a file, also makes this much less likely but still.

In any case, `signtool.exe` automatically and transparently takes care of issuing a new certificates when necessary. In this sense, it is very common to modern non-profit certificate authorities such as [Let's Encrypt](https://letsencrypt.com).

### 2.1. Pricing

The [pricing plan of Azure Trusted Signing](https://azure.microsoft.com/en-us/pricing/details/trusted-signing/) is based on a reasonable monthly fee with a maximum quota of signatures per month (e.g. 5000 signatures per month) after which a per-signature cost gets activated. There is also a bigger tier if you require much more signatures per month, e.g. if you're running extensive CI systems or such. Typically the smallest tier will probably work for most independent developers.

### 2.2. Setting up Azure Trusted Signing on Microsoft Azure

The following assumes that you have access to the Azure Trusted Signing service in your Microsoft Azure account.

These steps will involve using the Microsoft Azure web portal to configure things. It will only be necessary to configure these things _once_, and you should be good to go afterwards.

First of all, you will need to look up your tenant id in the Azure Portal:

* In the Azure portal, go to or search for [Microsoft Entra ID](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Overview).
* Your tenant id should be visible under Basic information.

💡 _Note down the tenant id, as we will be using this later in this guide._

#### 2.2.1. Creating a Trusted Signing Account

We will start by creating an _Trusted Signing Account_ on Azure.

1. Go to [Trusted Signing Accounts](https://ms.portal.azure.com/#browse/Microsoft.CodeSigning%2Fcodesigningaccounts)
2. Click "Create". Fill in the details, pick one of the following regions:
	* East US (https://eus.codesigning.azure.net)
	* West US (https://wus.codesigning.azure.net)
	* West Central US (https://wcus.codesigning.azure.net)
	* West US 2 (https://wus2.codesigning.azure.net)
	* North Europe (https://neu.codesigning.azure.net)  
	* West Europe (https://weu.codesigning.azure.net)

💡 _Note down the region, as we will be using this later in this guide._

#### 2.2.2. Granting administrative access

Now that we have a _Trusted Signing Account_, we need to grant your account administrative access in order to access it:

* Click on your Trusted Signing Account in [Trusted Signing Accounts](https://ms.portal.azure.com/#browse/Microsoft.CodeSigning%2Fcodesigningaccounts).
* Go to "Access control (IAM)" (left menu).
* Click "Add" and "Add role assignment" (top).
* Search for "Trusted Signing Identity Verifier" (job function roles). Next.
* Type in and select your current user account.
* Keep clicking "Review + assign" until done.

Your account should now have administrative access to Trusted Signing.

#### 2.2.3. Create a code signing app

We will now create a _code signing app_, for which the credentials will be used with `signtool.exe`:

* In the Azure portal, go to or search for [Microsoft Entra ID](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Overview).
* Click "Add" and "App registration" (top).
* Name: codesigning-app (or anything else)
* Who can use this application or access this API?: Accounts in this organizational directory only (Default Directory only - Single tenant)
* Redirect URI: (leave as is)
* Click "Register".
* Click on the app resource you've just created.
* Note down the "Application (client) ID" for later usage with signtool.
* Go to "Certificates & secrets" (left menu).
* Click "Client secrets" (top).
* Click "New client secret".
* Set "Expires" to the highest date possible.
* Click "Add".
* Note down the "Value", this is the secret for later usage with signtool.

💡 _Note down the code signing app client ID and client secret, which we will use later in this guide._

#### 2.2.4. Granting code signing app permissions

We will now grant Trusted Signing permissions to our code signing app:

* Click on your Trusted Signing Account in [Trusted Signing Accounts](https://ms.portal.azure.com/#browse/Microsoft.CodeSigning%2Fcodesigningaccounts).
* Go to "Access control (IAM)" (left menu).
* Click "Add" and "Add role assignment" (top).
* Select "Trusted Signing Certificate Profile Signer". Next.
* Leave "User, Group or Service principal" selected. Click on "+ Select Members".
* Type in and select your app name (e.g. codesigning-app).
* Keep clicking "Review + assign" until done.

#### 2.2.5. Verify identity

Now that the Trusted Signing resources have been set up, we need to set up Trusted Signing so it can issue new certificates for code signing.

_One very important requirement for this is that your personal or company identity has been validated with Microsoft Azure._

If you have not _validated_ yet, proceed as follows:

* Click on your Trusted Signing Account in [Trusted Signing Accounts](https://ms.portal.azure.com/#browse/Microsoft.CodeSigning%2Fcodesigningaccounts).
* Go to "Objects" -> "Identity validation" (left menu).
* Click "New" and "Public Trust" (top).
* Fill in the details. Note that Primary and Secondary E-mail(s) will not be published in any certificate. You may need a DUNS number as well.

Your mileage may vary, but expect the validation to take at least a day to be confirmed as it is a one-time verification that concerns your Microsoft Azure account.

#### 2.2.6. Create certificate profile

We now need to create a _certificate profile_, which we can use for code signing to issue new certificates:

* Click on your Trusted Signing Account in [Trusted Signing Accounts](https://ms.portal.azure.com/#browse/Microsoft.CodeSigning%2Fcodesigningaccounts).
* Go to "Objects" -> "Certificate profiles" (left menu).
* Click "Create" and "Public Trust" (top).
* Fill in a name and select the "Verified CN and O" appropriately (will appear when the identity validation process is done).
* Click "Create".

💡 _Note down the Name of the certificate profile, as we will using this later in this guide._

The certificate profile should now be set up correctly, so `signtool.exe` can create new certificates on demand.

👍 Our setup on the Microsoft Azure portal side of things should now be complete.

## 2.3. Setting up Azure Trusted Signing for code signing

Now that Trusted Signing has been configured in the Microsoft Azure portal, we can set up the code signing tools on our local machine or automated build machine.

The following steps assume that you have access to a machine running a recent version of Microsoft Windows, and you are able to execute commands in the command prompt with administrative rights.

#### 2.3.1. Preparing the Azure CLI

We will need to install the Azure Command-Line Interface tools in order to make `signtool.exe` work with Azure Trusted Signing. This only needs to be done once. The CLI tools will be installed on your system, and will be accessible from a command prompt afterwards.

* Install the [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-cli).

The CLI should be accessible from a command prompt afterwards. If you have one open, reopen it and run `az` to verify that it has been installed correctly.

We now need to create a "service principal" locally to enable our code signing tools to work. Use the following commands:

* Log in with the CLI using your admin/owner account:
	```dos
	az login
	```
    This will either open your browser, or give you a link through which you should log in to the Azure portal.
* Execute the following manual commands using the CLI
	```dos
	az ad sp create --id cf2ab426-f71a-4b61-bb8a-9e505b85bc2e
	az ad app permission grant --id cf2ab426-f71a-4b61-bb8a-9e505b85bc2e --api 00000003-0000-0000-c000-000000000000 --scope User.Read
	```

⚠ If you have issues logging into Azure with `az login`, specifically regarding tenant id's, you may have installed Azure before and used a different account (or tenant). You can always find your tenant ID in the Microsoft Azure Portal under [Microsoft Entra ID](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Overview). and pass this in with the `--tenant-id ...` argument if needed.

Note that these commands are only necessary once, in order to configure your system with the right credentials. There is no need to repeat these commands afterwards in case you just want to sign applications. The environment variables later in this guide will serve as a way to provide the necessary credentials instead.

### 2.3.2. Installing `signtool.exe` and Trusted Signing Dlib

`signtool.exe` is the **_official_** code signing tools distributed by Microsoft with Windows SDKs.

⚠ You should assume that the required version of `signtool.exe` is _not_ installed on your system. On older versions, Azure Trusted Signing will not work, and will not show meaningful errors. Furthermore, the [official docs](https://learn.microsoft.com/en-us/azure/trusted-signing/how-to-signing-integrations) on minimum SDK requirements _contain the wrong version numbers_ so best to disregard them. So make sure to follow the installation instructions here.

The minimum required version of signtool is _only_ included with Windows 11 SDK 10.0.22621.755 or higher, _or_ can be manually installed. We will manually install signtool using the [NuGet](https://www.nuget.org/downloads) package manager as is recommended:

1. Download `nuget.exe` from the [official site](https://www.nuget.org/downloads).
2. Open a command prompt and navigate to directory _where you want the signtool to be installed_.
3. Let's install both the correct `signtool.exe` as well as the Trusted Signing Dlib:
   ```dos
   nuget.exe install Microsoft.Windows.SDK.BuildTools -x
   nuget.exe install Microsoft.Trusted.Signing.Client
   ```
   Replace `nuget.exe` with the actual path where the executable resides.

The signtool should now be installed in a directory that is or starts with `Microsoft.Windows.SDK.BuildTools`. Make sure to locate the full path to the `signtool.exe`, e.g. `C:\sign\Microsoft.Windows.SDK.BuildTools\bin\10.0.26100.0\x64\signtool.exe`.

The Trusted Signing Dlib should be installed in a directory that is or starts with `Microsoft.Trusted.Signing.Client` such as: `Microsoft.Trusted.Signing.Client.1.0.95`. Make sure to locate the `Azure.CodeSigning.Dlib.dll` file, e.g. `C:\sign\Microsoft.Trusted.Signing.Client.1.0.95\bin\x64\Azure.CodeSigning.Dlib.dll` and double check that the platform directory (`x86` or `x64`) matches with the signtool's path above.

💡 _Note down the absolute paths to `signtool.exe` and `Azure.CodeSigning.Dlib.dll`, as we will be using them below._

Finally, make sure the .NET 6.0 runtime is installed:

* [.NET 6.0 runtime](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-6.0.9-windows-x64-installer). If this is not installed, signtool will fail silently without output.

### 2.3.3. Configuring signtool

We now need to create a metadata configuration JSON file to make the signtool work with Azure Trusted Signing. This JSON file can be placed anywhere you like.

Here, you will need the Azure Portal _region_ that you noted down before.

* Create a `metadata.json` file with the following contents (replace details accordingly):
	```
	{
		"Endpoint": "<Code Signing Account Endpoint URL>", 
		"CodeSigningAccountName": "<Code Signing Account Name>", 
		"CertificateProfileName": "<Certificate Profile Name>"
	} 
	```
	* Endpoint URL: choose according to the endpoint you've chosen for the Azure Trusted Signing:
		* East US (https://eus.codesigning.azure.net)
		* West US (https://wus.codesigning.azure.net)
		* West Central US (https://wcus.codesigning.azure.net)
		* West US 2 (https://wus2.codesigning.azure.net)
		* North Europe (https://neu.codesigning.azure.net)  
		* West Europe (https://weu.codesigning.azure.net)

💡 _Note down the absolute path to `metadata.json`, as we will be using them below._

We also require a number of environment variables to be set. These can be added either to the system globally, or can be set in your own scripts calling the sign tool on your own accord. Environment variables can be set as follows (note that quotes are not necessary on Windows):
```dos
set AZURE_TENANT_ID=...
```

Make sure the following environment variables are set and use the _tenant id_, _client id_ and _client secret_ from Azure Portal that you noted down before:

	* `AZURE_TENANT_ID`: The Microsoft Entra tenant (directory) ID. Use the value you noted down earlier. Can also be found in Microsoft Entra ID.
	* `AZURE_CLIENT_ID`: The client (application) ID of an App Registration in the tenant. Use the value you noted down earlier.
	* `AZURE_CLIENT_SECRET`: A client secret ("value") that was generated for the App Registration. Use the value you noted down earlier.

In addition, this guide and its scripts below use a few custom environment variables of their own:

* `ACS_DLIB` should point to the absolute filesystem path of the `Azure.CodeSigning.Dlib.dll` that was noted down.
* `ACS_JSON` should point to the absolute filesystem path of the `metadata.json` file that was created above and noted down.

All of the environment variables should be set in the command prompt in which you will be running signtool later, e.g.:
```dos
set AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000
set AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000
set AZURE_CLIENT_SECRET=...
set ACS_DLIB=C:\sign\Microsoft.Trusted.Signing.Client.1.0.95\bin\x64\Azure.CodeSigning.Dlib.dll
set ACS_JSON=C:\sign\metadata.json
```

### 2.3.4. Testing `signtool.exe`

We now need to make sure that `signtool.exe` is working and capable of using Azure Trusted Signing to sign executables, before doing anything else.

Pick an executable that you would like to sign for testing purposes. We will sign this executable just to see if the entire signing flow works.

In the command prompt that you have open, you run signtool accordingly, e.g.:

```
C:\sign\Microsoft.Windows.SDK.BuildTools\bin\10.0.26100.0\x64\signtool.exe sign /v /debug /fd SHA256 /tr "http://timestamp.acs.microsoft.com" /td SHA256 /dlib %ACS_DLIB% /dmdf %ACS_JSON% filetobesigned.exe
```

Make sure to use the absolute path to `signtool.exe` that you noted down earlier. Also replace the `filetobesigned.exe` with the executable that you want to sign. When you run this, you should immediately see messages involving Azure Trusted Signing, and your signing should be successful.

If you are seeing a list of certificates or an error about no certificates that could be used, you are likely using the _wrong_ version of signtool, possibly one included with an SDK installed on your system. Make sure to only use the signtool that you installed above.

If you are getting other errors, go through the guide again and make sure to double check every step. It is easy to make mistakes (e.g. typo's in the region URL) and almost every mistake will lead to a failure of signtool at this point.

### 2.3.4. Using `signtool.exe` with AAX `wraptool.exe`

Now that signtool is successfully using Azure Trusted Signing to sign executables, we can now proceed to making signtool with Azure Trusted Signing work with PACE's wraptool. The PACE wraptool relies on signtool for its certificates, but as of the latest update of this guide _does not support_ the official Microsoft signtool with the Trusted Signing Dlib. It _does_ support the _unofficial_ AzureSignTool, but as mentioned before, this is not the focus of this guide.

⚠ This guide goes as far as _signing_ with the PACE wraptool, not including any _wrapping_. For wrapping, the arguments are very similar but your mileage may vary.

⚠ Newer PACE SDKs provide a `--explicitsigningoptions` option, which seemingly does not seem to be working just yet.

It is necessary to work around the lack of PACE support by modifying the PACE wraptool. This works because the wraptool utility also relies on Microsoft's `signtool.exe` internally, and ProTools on Windows expects binaries to be signed with a whitelisted Microsoft certificate authority.

The normal flow for wraptool relies on either a certificate file and password (no longer possible due to HSM) or a sign id (HSM) to passed in by the developer, with no apparent support for any other tools or options. However, we can use utility scripts and let the wrap tool use these instead to injects all the necessary arguments for Azure Trusted Signing to work.

This section presents a stop-gap workaround while wraptools remains (partially) unsupported by PACE.

In order for this solution to work, make sure:

* Python 3 has been installed on the system. This is because the utility script below relies on it.
* Choose a directory on the system that is accessible and where you can place the utility scripts.

Now proceed by creating the utility scripts in the same folder:

1. Create a python file called `aax-signtool.py` with the following contents:
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

2. Create a batch file called `aax-signtool.bat` with the following contents in a directory of your choice:
	```dos
	@echo off
	
	:: KDSP Signtool wrapper for Eden SDK / AAX wraptool
	::
	:: wraptool invokes signtool but makes a lot of assumptions about how we're going to sign
	:: which are incompatible with Azure Trusted Signing.
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
	python "%root%\aax-signtool.py"
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

If you're curious as to what these utility scripts do, the purpose of these two scripts is:

	1. To hook the PACE wrap tool's call to Microsoft's sign tool, by acting as a proxy to the actual sign tool.
	2. To inject the proper command-line arguments to Microsoft's sign tool, along with the original arguments from the PACE wrap tool, so that Azure Trusted Signing will be used instead of the regular HSM code signing.
	3. To sanitize the arguments that the PACE wrap tool is passing to the Microsoft sign tool, so things don't break. This is specifically the purpose of the Python script, and is not ideal but necessary as this step is very complicated to do with batch scripting. Another option would've been a single Python script but it is unclear if the PACE wrap tool would've accepted this.

In any case, you should now be able to run `wraptool.exe` such that it invokes `signtool.exe` making use of Azure Trusted Signing. In order to this, you will need to pass the following arguments, e.g.:

```dos
wraptool.exe sign --signtool c:\sign\aax-signtool.bat --signid 1 --verbose --installedbinaries --account ... --password ... --wcguid ... --in ...
```

Where `c:\sign\aax-signtool.bat` should point its absolute path inside your chosen directory.

You can ignore the `--signid 1` argument, but it is necessary to make wraptool work as it expects this argument to be present (remember, it is still thinking we are using HSM code signing, which we are not). This argument is completely ignored and defused by the actual utility scripts.

You should now be able to code sign and wrap binaries using Azure Trusted Signing. Remember to use `wraptool.exe sign` for code signing AAX plugins, and `wraptool.exe wrap` for wrapping and code signing binaries such as standalone applications.

## 3. Final words

With any luck, you should now have Azure Trusted Signing working with `signtool.exe` to sign application binaries, as well as with `wraptool.exe` to hopefully sign and/or wrap binaries.

Your mileage may vary depending on your situation, but the above instructions have been shown to been helpful for a lot of people so far!

Happy hacking!

🐨🚀
