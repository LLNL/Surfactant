from pywinauto.application import Application, WindowSpecification
from pywinauto.findwindows import find_elements
from pywinauto.findbestmatch import MatchError
from pywinauto.timings import TimeoutError

from os import listdir, remove, system
from os.path import abspath, exists
from warnings import simplefilter
from shutil import copy, copy2
from ntpath import basename
from sys import exit, argv
from time import sleep
from json import loads
from re import sub

# Disable warnings
simplefilter("ignore", category=UserWarning)

# Passed in command line arguments as dictionary (flag: value)
args = {"-path": None, "-debug": "off", "-license": "Stepper"}

# List of controls that have elevated priority
desired = ["next", "yes", "finish", "ok", "start", "install", "complete"]
desired.extend(["full"])

# List of controls that threw an error and should not be touched
blacklisted = []
onTrial = ""


def parse_args() -> None:
    """Reads the command line arguments and creates a dictionary with settings
    that affect the behavior of the script. If any argument in 'args' is None,
    the script prints out correct usage and exits. For now, only the path of
    the installer is required. '-type' is automatically generated, but the
    '-debug' and '-license' arguments are both optional.

    Args:
        None.

    Returns:
        None.
    """

    # String that indicates correct cmd line argument usage
    flags = "-path '...' (optional) -debug [on/off] -license '...'"
    usage = "Usage: python setupstepper.py " + flags

    # Parse cmdargs into a dictionary
    for i in range(2, len(argv), 2):
        if argv[i - 1] in args:
            args[argv[i - 1]] = argv[i]
        else:
            exit(usage)

    # Ensure args have been set
    for key in args.keys():
        if args[key] is None:
            exit(usage)

    # Set installer type and expand path
    args["-path"] = abspath(args["-path"])
    args["-type"] = args["-path"].rpartition(".")[-1]

    if args["-debug"] == "on":
        print(args)


def launch_installer() -> Application:
    """Creates an application object and launches the desired installer based
    on the path supplied in the arguments. If the installer is an msi, it is
    launched with msiexec.

    Args:
        None.

    Returns:
        Application: The application object that started the installer.
    """

    # Create an application object
    app = Application()

    # Start application with proper arguments
    msiprefix = "msiexec /i " if (args["-type"] == "msi") else ""
    app = app.start(f"{msiprefix}\"{args['-path']}\"")

    # Wait for the application to start
    sleep(1.5 if (args["-type"] == "msi") else 0.75)

    return app


def get_controls(dialog: WindowSpecification) -> list:
    """Gathers relevant controls from the given dialog and organizes their
    class, name, and ID into a sublist that will be put into the 'controls'
    list.

    Args:
        dialog (WindowSpecification): The dialog to be analyzed.

    Returns:
        list: Contains sublists that contain information about each control.
    """

    controls = []

    # Initiate list of button names that shouldn't be considered
    unwantedControls = ["Static", "#32770", "CtrlNotifySink", "DirectUIHWND"]
    unwantedControls.extend(["SysLink", "TNewNotebookPage", "TNewNotebook"])

    editNumber = 1

    for child in dialog.children():
        childClass = child.friendly_class_name()

        # Assign edit control numbers appropriately
        if childClass == "Edit":
            childClass += str(editNumber)
            editNumber += 1

        # Dont include a non-selectable or unwanted control
        if not child.is_enabled() or (childClass in unwantedControls):
            continue

        # For readability, remove all special characters from non-text boxes
        name = child.texts()[0]

        if not childClass.startswith("Edit"):
            name = sub(r"^\W*|[^0-9a-zA-Z| ]+|\W*$", "", name)

        # For each control, make a sublist with Type, Text, and ID
        controls.append([childClass, name.lower(), child.control_id()])

    return controls


def get_priority_list(ctrl: list) -> list:
    """Creates a parallel list to 'ctrl' whose nth integer value represents
    the priority value of the nth control. Priority values are assigned
    based on various conditions that attempt to generalize the next best
    step that results in successful installation.

    Args:
        ctrl (list): The list of controls returned from get_controls().

    Returns:
        list: Has priority values for each control in its parallel list 'ctrl'.
    """

    priority = [0] * len(ctrl)

    for i in range(len(ctrl)):
        classname, text, controlId = ctrl[i]
        isEdit = classname.startswith("Edit")

        # Condition for license RadioButton
        licenseCond = not isEdit and (("agree" in text) or ("accept" in text))
        licenseCond = licenseCond and ("not" not in text)

        # Condition for presence of an edit box
        editCond = (args["-license"] != text) and isEdit
        editCond = editCond and not (text.startswith("c:"))
        editCondValue = len(text)

        # Condition for control text being in the desired list
        desiredCond = text in desired

        # Condition for controls to avoid
        badCond = (controlId in blacklisted) or (text == "cancel")
        badCond = badCond or ((text == "") and not isEdit)

        # Assign priority value
        if badCond:
            priority[i] = 0
        elif editCond:
            priority[i] = 4 + editCondValue
        elif desiredCond:
            priority[i] = 3
        elif licenseCond:
            priority[i] = 2
        else:
            priority[i] = 1

    return priority


def proceed(dialog: WindowSpecification, control: list, pVal: int) -> None:
    """Decides whether to interact with the control or to wait. If the
    installation has started, allow the interaction with any control to exit
    the installer that would disrupt the installation configuration beforehand.
    Buttons are clicked and Edits are scrolled and have their text changed.

    Args:
        dialog (WindowSpecification): The dialog box containing the 'controls'.
        control (list): Attributes of the control with the highest priority.
        pVal (int): The priority value of 'control'.

    Returns:
        None.
    """

    global onTrial

    # Decide whether to wait or to advance
    classname, text, controlId = control if (pVal != 0) else ["", "", ""]
    onTrial = controlId

    if "next" in text:
        onTrial = 0

    # Scroll down and change the text in the edit box to the license code
    if classname.startswith("Edit"):
        dialog[classname].scroll(direction="down", amount="end")
        dialog[classname].set_edit_text(args["-license"])
        blacklisted.append(onTrial)

    # Perform button press if we have advanced
    elif classname != "":
        dialog[text].click()

        # Add exit option once an install button has been pressed
        if text == "install" or text == "start":
            desired.append("exit")

    # Give the UI a chance to load controls if it hasn't
    else:
        sleep(0.2)


def step_through(app: Application) -> None:
    """The main loop that sorts the controls from the current dialog and steps
    through the installer. If the '-debug' flag is on, the list of controls are
    dumped in descending order of priority and the user can determine whether
    the next step is done manually or not.

    Args:
        app (Application): The Application object that started the installer.

    Returns:
        None.
    """

    controls = None

    while app.is_process_running():
        try:
            # Get dialog box and retry if none are found
            window = app.top_window().texts()[0]

            if window == "":
                continue

            dialog = app[window]

            # Get controls and sort them. Retry if no controls are found
            controls = get_controls(dialog)
            pl = get_priority_list(controls)

            if len(pl) == 0:
                continue

            pl, controls = (list(t) for t in zip(*sorted(zip(pl, controls))))
            pl.reverse()
            controls.reverse()

            # Print controls in debug mode
            autoStep = ""

            if args["-debug"] == "on":
                print("Controls for: " + window)
                print("--------------------------------")

                for control in controls:
                    print("> {: <15} {: <15}".format(*control))

                autoStep = input("\nENTER to step or type to manually step...")
                print()

            # Decide what to press next if debug mode allowed it
            if len(autoStep) == 0:
                proceed(dialog, controls[0], pl[0])

        except (RuntimeError, MatchError, TimeoutError) as e:
            # If a new process has been spawned, latch on to that one instead
            if str(e) == "No windows for that process could be found":
                # Indicates that the installer has unexpectedly terminated
                if controls is not None:
                    break

                print("Ensure that the installer is in focus.")

                if args["-debug"] == "on":
                    print(find_elements(active_only=True))

                # Best way to generally latch on to multiprocess installers
                app.connect(active_only=True, found_index=0)
                continue

            # If a control was the culprit, add it to the blacklist
            if onTrial not in blacklisted:
                blacklisted.append(onTrial)

            print(f"Error: {e}")

    print("Installer has terminated.")


def handle_transfers() -> None:
    """Read the list of files that the host machine wants and attempt to
    transfer them into the shared folder. 'done.txt' signals to the host
    that all of the files have been acknowledged.

    Args:
        None.

    Returns:
        None.
    """

    # Copy each file into the shared folder
    with open("V:\\files.txt", "r", encoding="utf-8") as f:
        for line in f.readlines():
            # The name for each file is changed to a variant of its path
            file = line.strip()
            newname = file[4:].replace("\\\\", "__")

            try:
                copy2(file, f"V:\\{newname}")
            except Exception as e:
                print(e)

    # Signal to the host that each file has finished copying
    with open(".\\done.txt", "w") as f:
        f.write("done")

    copy(".\\done.txt", "V:\\done.txt")
    remove(".\\done.txt")

    # "Sleep" until the host has finished processing files
    while exists("V:\\done.txt"):
        sleep(0.5)


def handle_file(fname: str) -> None:
    """If the file is a txt, it's assumed to be the arguments for the file
    that will be placed into the folder next, which it will run and step
    through. Finally, the file is deleted from the folder. The installer
    is meant to be copied (not moved) into the directory.

    Args:
        fname (str): The name of the file to inspect

    Returns:
        None.
    """

    global args

    if args["-debug"] == "on":
        print(f"file: {fname}")

    # Handle file transfers
    if basename(fname) == "files.txt":
        handle_transfers()
        return

    # Handle installer file
    if fname[-3:] != "txt":
        args["-path"] = fname

        try:
            # Open and execute the installer
            app = launch_installer()
            step_through(app)

            # Stop capturing output after a bit
            sleep(10)
            system("taskkill /f /im minifilter.exe")

            # Move results into the shared folder and cleanup
            remove(fname)
            sleep(5)
            copy(".\\results.txt", "V:\\results.txt")
            remove(".\\results.txt")

            # Wait for results.txt to transfer
            while exists("V:\\results.txt"):
                sleep(0.5)

            print("results.txt file move complete")
        except Exception as e:
            print(e)
            sleep(0.5)

        return

    # Parse txt into dict as json
    try:
        print("Processing text file as args...")
        with open(fname, "r") as f:
            argstr = f.readlines()[0]
            args = loads(argstr)

        # Remove file from folder
        remove(fname)
    except Exception as e:
        print(e)
        sleep(0.5)


def main() -> None:
    """Continously checks to see if any new file has been added to the shared
    folder. If it has, it passes the file path to the handler. This script is
    meant to always run on a windows VM with admin privileges.

    Args:
        None.

    Returns:
        None.
    """

    while True:
        # Retry if the shared folder doesn't exist
        if not exists("V:\\"):
            continue

        try:
            # Check for any files in the shared folder
            files = listdir("V:\\")

            if len(files) == 0:
                continue

            # Consider the next file in line
            files[0] = abspath("V:\\" + files[0])

            handle_file(files[0])
        except OSError as e:
            print(e)


if __name__ == "__main__":
    main()
