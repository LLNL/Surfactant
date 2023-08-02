from os import mkdir, getcwd, remove, makedirs, listdir
from os.path import abspath, exists
from shutil import copy, copy2
from sys import exit, argv
from time import sleep
from json import dumps

from virtualbox.library_base import VBoxError
from virtualbox import VirtualBox
from virtualbox import Session

# Passed in command line arguments
args = {"-machine": "WinDev2305Eval", "-path": None, "-debug": "off"}
args["-sfpath"] = getcwd() + "\\vb"

# Virtualbox global variables
vbox, machine, session = [None] * 3


def parse_args() -> None:
    """Reads the command line arguments and creates a dictionary with settings
    that affect the behavior of the script. If any argument in 'args' is None,
    the script prints out correct usage and exits. The user must specify the
    target vm name and the path of the installer.

    Args:
        None.

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
            exit(f"{argv[i - 1]} is not a valid argument.\n" + usage)

    # Ensure args have been set
    for key in args.keys():
        if args[key] is None:
            exit(f"{key} is a required argument.\n" + usage)

    # Ensure that the user has selected a valid vm name
    names = [m.name for m in vbox.machines]

    if args["-machine"] not in names:
        exit(f"'{args['-machine']}' isn't in your vm list: \n{names}")

    # Expand installer paths
    args["-path"] = abspath(args["-path"])
    args["-type"] = args["-path"].rpartition(".")[-1]


def prepare_vm() -> None:
    """Boots up the specified virtual machine and transfers the specified
    installer from the host machine.

    IMPORTANT: For this to work, the target machine must be in a SAVED state
    and NOT running on VirtualBox. This will allow the session to obtain the
    write lock. Also, waiting for the OS to fully boot is a complex task, so
    restoring the VM from a saved state greatly simplifies the process.

    Args:
        None.

    Returns:
        None.
    """

    global machine

    # Create the shared folder on the host machine
    if not exists(args["-sfpath"]):
        mkdir(args["-sfpath"])

    # Retrieve machine and boot it
    try:
        machine = vbox.find_machine(args["-machine"])
        progress = machine.launch_vm_process(session, "gui", [])
        progress.wait_for_completion()
    except VBoxError as e:
        print(e)
        exit("Ensure the VM is in a saved and non-running state.")

    # Create the shared folder on the guest machine's V: drive
    try:
        sMachine = session.machine
        sMachine.create_shared_folder("vb", args["-sfpath"], True, True, "V:")
    except VBoxError as e:
        print(e)

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
        with open("args.txt", "w") as f:
            f.write(dumps(args, separators=(",", ":")))

        copy("args.txt", args["-sfpath"])
        remove("args.txt")
    except PermissionError as e:
        print(e)
        exit("Make sure the files are in the current directory!")

    try:
        # Deploy installer
        copy(args["-path"], args["-sfpath"])
    except PermissionError as e:
        print(e)
        exit("Make sure the files are in the current directory!")

    # Busy wait until the installer is done
    while not exists(args["-sfpath"] + "\\results.txt"):
        sleep(0.1)

    # Retrieve results
    sleep(2)
    copy(args["-sfpath"] + "\\results.txt", getcwd())
    remove(args["-sfpath"] + "\\results.txt")


def cleanup() -> None:
    """Cleans up the shared folder from extra files, if possible, then powers
    down the VM and restores it from the state it started as. The Snapshot
    should be called "TestState" for this to work, but it can be changed.

    Args:
        None.

    Returns:
        None.
    """

    # Cleanup the shared folder
    for file in listdir(".\\vb"):
        try:
            remove(".\\vb\\" + file)
        except Exception as e:
            print(f"CANNOT DELETE .\\vb\\{file}: {str(e)}")

    # Save settings and power down the machine
    session.machine.save_settings()
    progress = session.console.power_down()
    progress.wait_for_completion()

    # Get latest snapshot and restore it
    snapshot = session.machine.find_snapshot("TestState")
    progress = session.machine.restore_snapshot(snapshot)
    progress.wait_for_completion()

    session.unlock_machine()


def analyze_results() -> list:
    """Analyzes the results.txt file and filters out the irrelevant files.
    The newly created file lists files that should be extracted from the VM.

    Args:
        None.

    Returns:
        list: contains the filtered list of files that should be extracted.
    """

    # Ensure that results.txt has been moved
    fname = ".\\results.txt"
    if not exists(fname):
        return

    print("processing results.txt...")

    # Load file data
    lines = None

    with open(fname, "r", encoding="utf-16") as fp:
        lines = fp.readlines()

    remove(fname)

    # get parallel lists ready, prevent reading an incomplete file
    nfiles = len(lines) // 7

    filename = [""] * nfiles
    extension = [""] * nfiles
    executable = [""] * nfiles
    pid = [""] * nfiles
    irp_op = [""] * nfiles
    change_code = [""] * nfiles

    for i in range(nfiles):
        idx = i * 7

        # Interpret the extension buffer correctly
        ext = str(lines[idx + 2]).strip("[] \t\r\n")
        extension[i] = "".join([chr(int(x)) for x in ext.split(", ")])

        # Construct the file name and fix the duplicate extension
        currfname = str(lines[idx + 1]).split(".", 1)[0].strip('" \t\r\n')
        currfname = "BAD:" if len(currfname) == 0 else currfname
        filename[i] = currfname + "." + extension[i]

        # Get the rest of the attributes from the file
        exename = str(lines[idx + 3]).rstrip().strip('"')
        executable[i] = "BAD" if len(exename) == 0 else exename
        pid[i] = int(str(lines[idx + 4]).rstrip())
        irp_op[i] = int(str(lines[idx + 5]).rstrip())
        change_code[i] = int(str(lines[idx + 6]).rstrip())

    # Create auxillary lists
    aux_fname = []
    aux_ext = []
    aux_exe = []
    aux_pid = []
    aux_irp_op = []
    aux_change_code = []

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
        if (filename[i] in aux_fname) or filename[i].startswith("BAD:"):
            continue

        # Filter out bad executables and file reads
        if executable[i].startswith("BAD") or (irp_op[i] == 1):
            continue

        # Filter out file deletions
        if change_code[i] == 6:
            continue

        # Filter out blacklisted executables and files
        skip = False
        for badexe in badexes:
            if badexe in executable[i]:
                skip = True

        for badfile in badfiles:
            if badfile in filename[i]:
                skip = True

        if skip:
            continue

        # Add unique file to the lists
        aux_fname.append(filename[i])
        aux_ext.append(extension[i])
        aux_exe.append(executable[i])
        aux_pid.append(pid[i])
        aux_irp_op.append(irp_op[i])
        aux_change_code.append(change_code[i])

    if args["-debug"] == "off":
        return aux_fname

    # Reassign list references
    filename = aux_fname
    extension = aux_ext
    executable = aux_exe
    pid = aux_pid
    irp_op = aux_irp_op
    change_code = aux_change_code

    # Keep intermediate file for debugging
    nfiles = len(filename)

    with open("filtered.txt", "w", encoding="utf-8") as fp:
        for i in range(nfiles):
            fp.write(f"File {i}:\n")
            fp.write(f"{'Name:':<10} {filename[i]}\n")
            fp.write(f"{'Exe File:':<10} {executable[i]}\n")
            fp.write(f"{'PID/ops:':<10} {pid[i]} {irp_op[i]} {change_code[i]}")
            fp.write("\n\n")

    return filename


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
    with open(".\\files.txt", "w", encoding="utf-8") as f:
        for file in files:
            # Edit file path for the VM file to be the file path for a C folder
            dirs = ".\\C\\" + "\\".join(file.split("\\\\")[1:-1]) + "\\"
            newdirs.append(dirs)

            # Add to the list of files. Remove mysterious 21 space characters
            file = file[:-21]
            f.write(file.replace(chr(0), ""))
            f.write("\n")

    copy(".\\files.txt", ".\\vb\\files.txt")

    if args["-debug"] == "off":
        remove(".\\files.txt")

    # Wait for the vm to send back all of the files
    while not exists(".\\vb\\done.txt"):
        sleep(0.5)

    remove(".\\vb\\files.txt")

    # Move files from the shared folder to their new path
    for i in range(len(files)):
        # The correct path for the new file is just a variant of its name
        file = files[i][4:].replace("\\\\", "__")
        newpath = f".\\\\C\\\\{files[i][4:]}"
        newpath = newpath.replace(chr(0), "")
        sharedfile = f".\\vb\\{file}".replace(chr(0), "")

        # Write to the list of unsuccessful files if the file doesn't exist
        if not exists(sharedfile):
            print(f"Failure: {newpath}")
            print(" --> [Errno 2] No such file or directory")

            with open(".\\otherpaths.txt", "a") as f2:
                f2.write("C:" + newpath.replace("\\\\", "\\")[3:] + "\n")

            continue

        try:
            # If the file exists, make the directories for it and copy it in
            makedirs(newdirs[i], exist_ok=True)
            copy2(sharedfile, newpath)
            print(f"Success: {newpath}")

            # Write to the list of successful files
            with open(".\\finalpaths.txt", "a") as f1:
                f1.write("C:" + newpath.replace("\\\\", "\\")[3:] + "\n")

            remove(sharedfile)
        except Exception as e:
            # Since we know the file exists, deal with access errors
            print(f"Copy/Removal Failure: {newpath}")
            print(" --> " + str(e))

    # Signal to vm that all files have been transferred
    remove(".\\vb\\done.txt")


def main() -> None:
    """Handles command line parsing and executes each segment.

    Args:
        None.

    Returns:
        None.
    """

    # Initiate global variables
    global vbox, session

    vbox = VirtualBox()
    session = Session()

    # Read command line arguments and start the VM
    parse_args()
    prepare_vm()

    # Skip over to cleanup if a fatal error happened when deploying installer
    try:
        # Send installer to VM
        deploy_installer()

        # Extract files from VM
        files = analyze_results()
        recreate_dirs(files)
    except Exception as e:
        print(e)

    # Restore VM to previous state
    cleanup()


if __name__ == "__main__":
    main()
