# Setting up a Windows Installer SBOM Generation Workflow

## Summary
When working with Windows software installers, it's often not obvious where the installer places its files. With this setup, the installer is run in a modified VirtualBox VM that has a file system driver installed. This tool uses the file system driver to determine what files came from the installer and extracts them from the VM into the host machine. The extracted files are then placed into a directory structure on the host that mimics the guest file system VM, except instead of the `C:` drive, the files are placed into a subfolder named `C` which only contains those files extracted from the VM. Running Surfactant on this folder can be essentially be used to create SBOMs for almost any installer.

Following these instructions result in a working VM. The mentioned process has been made entirely automatic by running a single command. Configuration settings are near the bottom and should be considered before setting up the VM.

## Sections for Host Setup
### Install VirtualBox and the SDK

Go to https://www.virtualbox.org/wiki/Download_Old_Builds_7_0. Install VirtualBox version 7.0.8.

To install the python API, in an administrator powershell (for Windows hosts) run:

```shell
python -m pip install virtualbox
```

### Install Windows 11 VM

Go to https://developer.microsoft.com/enus/windows/downloads/virtual-machines/. Under the "Download a virtual machine" section, select the "VirtualBox" option to download the zipped file. Extract the zipped file anywhere you want. Open VirtualBox and select `Machine -> Import Appliance`. Choose the .ova file that was extracted earlier and hit "Next" then "Finish."

### Disable Hyper-V (Optional)

On a Windows host, VirtualBox VMs run better with Hyper-V disabled. In administrator command prompt, run
```shell
bcdedit /set hypervisorlaunchtype off
```
and restart.

### Prepare the driver

Go to https://github.com/SubconsciousCompute/fsfilter-rs/releases/tag/v0.8.0 and download the "Source code" zip and extract it to this folder. To apply the patch file, run (on Linux/WSL)
```shell
patch -s -p0 < fsfilter.patch
```

## Sections for VM Setup
### Enable shared clipboard

In the top bar, go to `Devices -> Shared Clipboard` and select "Host To Guest" to make it easier on yourself to run commands.

### Enable Administrator account

Start up the VM and let it run its first time setup. Open "terminal" as administrator and run
```shell
net user "Administrator" /active:yes
```
and then
```shell
net user USER password
```
in the prompt. In the Start Menu, sign out of "USER" and login to Administrator with "password" as the password. Once the first time setup is done, pin "Terminal" to the taskbar to make it easy on yourself for later steps. Sadly Windows has heavy visual bugs on VirtualBox, so opening apps from the taskbar avoids most of that.

### Install python and pywinauto

In the Microsoft Store, install the latest python. In powershell, run
```shell
python -m pip install --upgrade pip
```
and
```shell
pip install pywinauto
```
to install the libraries needed for the scripts.

### Move files into the VM

In the VirtualBox VM manager on the VM, select Settings -> Shared Folders, then select AutoInstallerTool and leave the "Mount point" field blank, check "Auto-mount" then hit OK. From the shared folder (probably the Z: volume), move `fsfilter-rs-0.8.0/` and `setupstepper.py` into the Documents directory (anywhere works).

### Install Rust

Open Edge, select "Start without your data" and "Continue without this data" and Uncheck the box and "Confirm and continue" and Uncheck the box again and "Confirm and start browsing." Finally, go to https://www.rust-lang.org/tools/install and download Rustup-init.exe as 64-bit. Disconnect from any corporate networks to avoid certificate issues from now on. Open the installer in powershell, type 1 to select `Proceed with installation (default)`, then hit Enter. Once that's done, hit Enter and close
the shell.

### Download the EWDK

Go to https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk and download the EWDK under the section that comes right before "Driver samples for Windows" and accept the license terms. This file is several gigabytes and may take some time to download.

### Enable unsigned drivers

Hit `Win + X` on the keyboard and select `Shut down or sign out` and then `Shift + Click` the `Restart` option. Then, `Troubleshoot -> Advanced options -> Start-up Settings -> Restart -> "Disable driver signature enforcement"` which can be selected by hitting "7" on the keyboard. Now you can sign out and login as Administrator again.

### Build the driver and run it

Right click on the downloaded EWDK and mount it. It might get mounted to the `D:` drive, so I'll refer to that one. Open "cmd" in the `fsfilter-rs-0.8.0/minifilter` directory and run
```shell
call "D:\LaunchBuildEnv.cmd"
```
then to build the minifilter, run
```shell
msbuild RWatch.sln /m /p:configuration=Release /p:platform=x64 /p:RunCodeAnalysis=false
```
and close the prompt once it's done. You should now eject the EWDK. Go to `fsfilter-rs-0.8.0/minifilter/x64/Release/` and open powershell to run
```shell
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 .\snFilter.inf
```
and select the "Install this driver software anyway" option.

### Build the minifilter

From the `fsfilter-rs-0.8.0/` directory in powershell, run
```shell
cargo build --release
```
The compiled minifilter.exe should reside in `fsfilter-rs-0.8.0/target/release/minifilter.exe`. Move this executable into the Documents folder. Finally, run
```shell
Bcdedit.exe -set TESTSIGNING ON
```
then shut down the machine and create a snapshot in case something goes wrong.

### Setup the runtime environment

Turn on the VM again and log in. Open a powershell window and run
```shell
Start-Service snFilter
```
to start the driver. Open a second powershell window. On both windows, navigate to Documents. On one window, type (but don't run)
```shell
minifilter.exe > results.txt
```
and type (but don't run)
```shell
python ./setupstepper.py
```
in the other window. Run the minifilter command first then the python command in quick succession, it doesn't have to be insanely fast. On the taskbar, select `File -> Close -> "Save the machine state"` and let it close. Create a snapshot called "TestState" and let it save.

## Running
### These steps are done on the host machine.

Copy the installer of your choice into any directory together with `execinstaller.py`. In an administrator shell, run
```shell
python execinstaller.py -path [path to installer]
```
and wait. The VM should startup, execute the installer, then close. In the same directory you should see a directory called "C" which contains the full paths of the installed files. Two txt files are created. One that lists the extracted files, and one that lists files that were detected but could not be extracted (most likely temp files). The script tries to clean up the shared folder, but you should manually make sure that the folder is empty before testing the script on another installer.

### Options

`-path [Installer path]` (Mandatory): The path of the installer (such as `-path ./ICsetup.exe`) that the VM should step through.

`-license [key]` (Optional): If the installer has a license key, enter it here (such as `-license 1234`)

`-debug [on|off]` (Optional): Manually step through the installer and don't delete unfiltered minifilter.exe output

`-machine [VM name]` (Optional): Specify the name of the VM to start.

### Configuration
To set a default machine name, edit `execinstaller.py` at line 13.

To set the name of the snapshot that you'd like the VM to restore to, edit `execinstaller.py` at line 27.

To set the name of the shared folder that will be created, edit `execinstaller.py` at line 18.

Lines 20 - 26 in `execinstaller.py` contain string constants that mostly consist of file names that will be created and deleted throughout runtime. The `EXTRACTED` and `NOT_EXTRACTED` constants denote the output files. the other constants are the names of other files which are created and deleted throughout runtime. If you want to edit the names of these other files, make sure they remain consistent with lines 24 - 26 in `setupstepper.py`.

## Potential Issues
### Note on filtering
If the installed files aren't showing up, you can set the debug flag and unfilter out executable and file names in `execinstaller.py` at lines 246 and 249. The filter works by excluding file names that contain the specified substring.

### Note on installer failure during step-through
If the installer runs into a dependency error, you can manually exit the installer and let the script finish to capture potential temporary files. You can also try to run it again after installing the dependency in the VM.

### Note on VM crashing upon opening the installer
If the script running within the vm acknowledges the args.txt file before crashing, shut down the machine and restore to the TestState snapshot and try again. This happens for unknown reasons.

### Note on VirtualBox errors
If you get an error that reads "The instruction at 0x... referenced memory at 0x... The memory could not be written" or similar, hit "OK" and revert the VM to the safe powered-off snapshot. Follow the steps to run the commands on both terminals and try again. The green/red flashing light on the leftmost icon indicates activity on the disk, so try to press "Close" when a light isn't on to avoid interrupting the machine during a disk read/write.
