""" execinstaller.py """
import sys
from json import dumps
from os import getcwd, listdir, makedirs, mkdir, remove
from os.path import abspath, exists
from shutil import copy, copy2
from sys import argv
from time import sleep

from virtualbox import Session, VirtualBox
from virtualbox.library_base import VBoxError

# Passed in command line arguments
args = {"-machine": "WinDev2307Eval", "-path": None, "-debug": "off"}
args["-sfpath"] = getcwd() + "\\vb"


def parse_args(vbox: VirtualBox) -> None:
    """Reads the command line arguments and creates a dictionary with settings
    that affect the behavior of the script. If any argument in 'args' is None,
    the script prints out correct usage and exits. The user must specify the
    target vm name and the path of the installer.

    Args:
        vbox (VirtualBox): Primary VB object

    Returns:
        None.
    """

    # String that indicates correct cmd line argument usage
    flags = "-machine '...' -path '...' (optional) -license '...'"
    usage = "Usage: python execinstaller.py " + flags

    args["-license"] = "Stepper"

    # Parse cmdargs into a dictionary
    for i in range(2, len(argv), 2):
        if argv[i - 1] in args:
            args[argv[i - 1]] = argv[i]
        else:
            sys.exit(f"{argv[i - 1]} is not a valid argument.\n" + usage)

    # Ensure args have been set
    for key, value in args.items():
        if value is None:
            sys.exit(f"{key} is a required argument.\n" + usage)

    # Ensure that the user has selected a valid vm name
    names = [m.name for m in vbox.machines]

    if args["-machine"] not in names:
        sys.exit(f"'{args['-machine']}' isn't in your vm list: \n{names}")

    # Expand installer paths
    args["-path"] = abspath(args["-path"])
    args["-type"] = args["-path"].rpartition(".")[-1]


def prepare_vm(vbox: VirtualBox, session: Session) -> None:
    """Boots up the specified virtual machine and transfers the specified
    installer from the host machine.

    IMPORTANT: For this to work, the target machine must be in a SAVED state
    and NOT running on VirtualBox. This will allow the session to obtain the
    write lock. Also, waiting for the OS to fully boot is a complex task, so
    restoring the VM from a saved state greatly simplifies the process.

    Args:
        vbox (VirtualBox): Primary VB object
        session (Session): Session associated with vbox

    Returns:
        None.
    """

    # Create the shared folder on the host machine
    if not exists(args["-sfpath"]):
        mkdir(args["-sfpath"])

    # Retrieve machine and boot it
    try:
        machine = vbox.find_machine(args["-machine"])
        progress = machine.launch_vm_process(session, "gui", [])
        progress.wait_for_completion()
    except VBoxError as err:
        print(err)
        sys.exit("Ensure the VM is in a saved and non-running state.")

    # Create the shared folder on the guest machine's V: drive
    try:
        s_machine = session.machine
        s_machine.create_shared_folder("vb", args["-sfpath"], True, True, "V:")
    except VBoxError as err:
        print(err)

    # Save settings on the machine
    session.machine.save_settings()


def deploy_installer() -> None:
    """Inserts intaller and required arguments into the shared folder. Once
    the VM has finished executing the installer, the 'results.txt' file is
    retrieved from the VM.

    Args:
        None.

    Returns:
        None.
    """

    try:
        # Insert arguments into shared folder
        with open("args.txt", "w", encoding="utf-8") as f_handle:
            f_handle.write(dumps(args, separators=(",", ":")))

        copy("args.txt", args["-sfpath"])
        remove("args.txt")
    except PermissionError as err:
        print(err)
        sys.exit("Make sure the files are in the current directory!")

    try:
        # Deploy installer
        copy(args["-path"], args["-sfpath"])
    except PermissionError as err:
        print(err)
        sys.exit("Make sure the files are in the current directory!")

    # Busy wait until the installer is done
    while not exists(args["-sfpath"] + "\\results.txt"):
        sleep(0.1)

    # Retrieve results
    sleep(2)
    copy(args["-sfpath"] + "\\results.txt", getcwd())
    remove(args["-sfpath"] + "\\results.txt")


def cleanup(session: Session) -> None:
    """Cleans up the shared folder from extra files, if possible, then powers
    down the VM and restores it from the state it started as. The Snapshot
    should be called "TestState" for this to work, but it can be changed.

    Args:
        session (Session): Session associated with vbox

    Returns:
        None.
    """

    # Cleanup the shared folder
    for file in listdir(".\\vb"):
        try:
            remove(".\\vb\\" + file)
        except IOError as err:
            print(f"CANNOT DELETE .\\vb\\{file}: {str(err)}")

    # Save settings and power down the machine
    session.machine.save_settings()
    progress = session.console.power_down()
    progress.wait_for_completion()

    # Get latest snapshot and restore it
    snapshot = session.machine.find_snapshot("TestState")
    progress = session.machine.restore_snapshot(snapshot)
    progress.wait_for_completion()

    session.unlock_machine()


def get_attributes() -> list:
    """Reads from results.txt and returns the list of files

    Args:
        None.

    Returns:
        list: contains the attributes for each file
    """

    # Ensure that results.txt has been moved
    fname = ".\\results.txt"
    if not exists(fname):
        return []

    print("processing results.txt...")

    # Load file data
    lines = None

    with open(fname, "r", encoding="utf-16") as f_handle:
        lines = f_handle.readlines()

    remove(fname)

    # get parallel lists ready, prevent reading an incomplete file
    nfiles = len(lines) // 7
    attr = [[""] * nfiles] * 6

    for i in range(nfiles):
        idx = i * 7

        # Interpret the extension buffer correctly
        ext = str(lines[idx + 2]).strip("[] \t\r\n")
        attr[1][i] = "".join([chr(int(x)) for x in ext.split(", ")])

        # Construct the file name and fix the duplicate extension
        currfname = str(lines[idx + 1]).split(".", 1)[0].strip('" \t\r\n')
        currfname = "BAD:" if len(currfname) == 0 else currfname
        attr[0][i] = currfname + "." + attr[1][i]

        # Get the rest of the attributes from the file
        exename = str(lines[idx + 3]).rstrip().strip('"')
        attr[2][i] = "BAD" if len(exename) == 0 else exename
        attr[3][i] = int(str(lines[idx + 4]).rstrip())
        attr[4][i] = int(str(lines[idx + 5]).rstrip())
        attr[5][i] = int(str(lines[idx + 6]).rstrip())

    return attr


def analyze_results() -> list:
    """Analyzes the results.txt file and filters out the irrelevant files.
    The newly created file lists files that should be extracted from the VM.
    Attribute indices: 0 = filename, 1 = extension, 2 = executable,
    3 = pid, 4 = irp_operation, 5 = change_code

    Args:
        None.

    Returns:
        list: contains the filtered list of files that should be extracted.
    """

    # Create auxillary lists
    attr = get_attributes()
    nfiles = len(attr[0])
    aux_attr = [] * 6

    # List of unwanted exe substrings
    badexes = ["msteams", "TiWorker", "MicrosoftEdge", "MoUsoCoreWorker"]
    badexes.extend(["DeviceCensus", "msedge", "TrustedInstaller", "UsoClient"])
    badexes.extend(["MpSigStub", "OneDrive", "RuntimeBroker", "TaskHost"])
    badexes.extend(["Notepad", "Microsoft.SharePoint", "taskhostw", "svchost"])
    badexes.extend(["SecurityHealthHost", "MpCmdRun", "conhost", "dllhost"])
    badexes.extend(["MoNotificationUx", "taskkill", "CompatTelRunner"])
    badexes.extend(["python"])

    # List of unwanted file substrings
    badfiles = ["Prefetch", "taskkill"]

    # Remove duplicates and bad substrings
    for i in range(nfiles):
        # Remove duplicates and bad files
        if (attr[0][i] in aux_attr[0]) or attr[0][i].startswith("BAD:"):
            continue

        # Filter out bad executables and file reads
        if attr[2][i].startswith("BAD") or (attr[4][i] == 1):
            continue

        # Filter out file deletions
        if attr[5][i] == 6:
            continue

        # Filter out blacklisted executables and files
        skip = False
        for badexe in badexes:
            if badexe in attr[2][i]:
                skip = True

        for badfile in badfiles:
            if badfile in attr[0][i]:
                skip = True

        if skip:
            continue

        # Add unique file to the lists
        for j in range(6):
            aux_attr[j].append(attr[j][i])

    if args["-debug"] == "off":
        return aux_attr[0]

    # Reassign list references
    attr = aux_attr

    # Keep intermediate file for debugging
    nfiles = len(attr[0])

    with open("filtered.txt", "w", encoding="utf-8") as f_handle:
        for i in range(nfiles):
            f_handle.write(f"File {i}:\n")
            f_handle.write(f"Name:     {attr[0][i]}\n")
            f_handle.write(f"Exe File: {attr[2][i]}\n")
            f_handle.write(f"PID/ops:  {attr[3][i]} {attr[4][i]} {attr[5][i]}")
            f_handle.write("\n\n")

    return attr[0]


def recreate_dirs(files: list) -> None:
    """Asks the VM to extract files created by the installer. Files that are
    successfully extracted are listed in "finalpaths.txt" and those that
    were not successful are listed in "otherpaths.txt". The files are then
    placed into an empty "C" volume within their full install paths. One can
    then run Surfactant on the skeleton "C" directory.

    Args:
        files (list): The list of files that the VM will attempt to retrieve.

    Returns:
        None.
    """

    newdirs = []

    # Send the list of desired files to the vm
    with open(".\\files.txt", "w", encoding="utf-8") as f_handle:
        for file in files:
            # Edit file path for the VM file to be the file path for a C folder
            dirs = ".\\C\\" + "\\".join(file.split("\\\\")[1:-1]) + "\\"
            newdirs.append(dirs)

            # Add to the list of files. Remove mysterious 21 space characters
            file = file[:-21]
            f_handle.write(file.replace(chr(0), ""))
            f_handle.write("\n")

    copy(".\\files.txt", ".\\vb\\files.txt")

    if args["-debug"] == "off":
        remove(".\\files.txt")

    # Wait for the vm to send back all of the files
    while not exists(".\\vb\\done.txt"):
        sleep(0.5)

    remove(".\\vb\\files.txt")

    # Move files from the shared folder to their new path
    num_files = len(files)

    for i in range(num_files):
        # The correct path for the new file is just a variant of its name
        file = files[i][4:].replace("\\\\", "__")
        newpath = f".\\\\C\\\\{files[i][4:]}"
        newpath = newpath.replace(chr(0), "")
        sharedfile = f".\\vb\\{file}".replace(chr(0), "")

        # Write to the list of unsuccessful files if the file doesn't exist
        if not exists(sharedfile):
            print(f"Failure: {newpath}")
            print(" --> [Errno 2] No such file or directory")

            with open(".\\otherpaths.txt", "a", encoding="utf-8") as f_handle:
                f_handle.write("C:" + newpath.replace("\\\\", "\\")[3:] + "\n")

            continue

        try:
            # If the file exists, make the directories for it and copy it in
            makedirs(newdirs[i], exist_ok=True)
            copy2(sharedfile, newpath)
            print(f"Success: {newpath}")

            # Write to the list of successful files
            with open(".\\finalpaths.txt", "a", encoding="utf-8") as f_handle:
                f_handle.write("C:" + newpath.replace("\\\\", "\\")[3:] + "\n")

            remove(sharedfile)
        except OSError as err:
            # Since we know the file exists, deal with access errors
            print(f"Copy/Removal Failure: {newpath}")
            print(" --> " + str(err))

    # Signal to vm that all files have been transferred
    remove(".\\vb\\done.txt")


def main() -> None:
    """Handles command line parsing and executes each segment.

    Args:
        None.

    Returns:
        None.
    """

    # Initiate VirtualBox variables
    vbox = VirtualBox()
    session = Session()

    # Read command line arguments and start the VM
    parse_args(vbox)
    prepare_vm(vbox, session)

    # Skip over to cleanup if a fatal error happened when deploying installer
    try:
        # Send installer to VM
        deploy_installer()

        # Extract files from VM
        files = analyze_results()
        recreate_dirs(files)
    except OSError as err:
        print(err)

    # Restore VM to previous state
    cleanup(session)


if __name__ == "__main__":
    main()
