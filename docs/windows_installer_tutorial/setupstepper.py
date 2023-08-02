<<<<<<< HEAD
from json import loads
from ntpath import basename
from os import listdir, remove, system
from os.path import abspath, exists
=======
from os import listdir, remove, system
from os.path import abspath, exists
from warnings import simplefilter
from shutil import copy, copy2
from ntpath import basename
from time import sleep
from json import loads
>>>>>>> fe3f1e8 (Fixed some pylint warnings)
from re import sub
from shutil import copy, copy2
from sys import argv, exit
from time import sleep
from warnings import simplefilter

from pywinauto.application import Application, WindowSpecification
from pywinauto.findbestmatch import MatchError
from pywinauto.findwindows import find_elements
from pywinauto.timings import TimeoutError

from pywinauto.application import Application, WindowSpecification
from pywinauto.findwindows import find_elements
from pywinauto.findbestmatch import MatchError

# Disable warnings
simplefilter("ignore", category=UserWarning)

# Passed in command line arguments as dictionary (flag: value)
arguments = {"-path": None, "-debug": "off", "-license": "Stepper"}

# List of controls that have elevated priority
desired = ["next", "yes", "finish", "ok", "start", "install", "complete"]
desired.extend(["full"])

# List of controls that threw an error and should not be touched
blacklisted = []


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
    msiprefix = "msiexec /i " if (arguments["-type"] == "msi") else ""
    app = app.start(f"{msiprefix}\"{arguments['-path']}\"")

    # Wait for the application to start
    sleep(1.5 if (arguments["-type"] == "msi") else 0.75)

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

    numControls = len(ctrl)
    priority = [0] * numControls

    for i in range(numControls):
        classname, text, controlId = ctrl[i]
        isEdit = classname.startswith("Edit")

        # Condition for license RadioButton
        licenseCond = not isEdit and (("agree" in text) or ("accept" in text))
        licenseCond = licenseCond and ("not" not in text)

        # Condition for presence of an edit box
        editCond = (arguments["-license"] != text) and isEdit
        editCond = editCond and not text.startswith("c:")
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

    # Decide whether to wait or to advance
    classname, text, controlId = control if (pVal != 0) else ["", "", ""]

    # If a control was the culprit, add it to the blacklist
    onTrial = 0 if "next" in text else controlId
    blacklisted.append(onTrial)

    # Scroll down and change the text in the edit box to the license code
    if classname.startswith("Edit"):
        dialog[classname].scroll(direction="down", amount="end")
        dialog[classname].set_edit_text(arguments["-license"])
        blacklisted.pop()
        blacklisted.append(controlId)

    # Perform button press if we have advanced
    elif classname != "":
        dialog[text].click()
        blacklisted.pop()

        # Add exit option once an install button has been pressed
        if text in ("install", "start"):
            desired.append("exit")

    # Give the UI a chance to load controls if it hasn't
    else:
        blacklisted.pop()
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

            if arguments["-debug"] == "on":
                print("Controls for: " + window)
                print("--------------------------------")

                for control in controls:
                    print(f"> {control[0]: <15} {control[1]: <15}")

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

                if arguments["-debug"] == "on":
                    print(find_elements(active_only=True))

                # Best way to generally latch on to multiprocess installers
                app.connect(active_only=True, found_index=0)
                continue

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
            except IOError as e:
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

    if arguments["-debug"] == "on":
        print(f"file: {fname}")

    # Handle file transfers
    if basename(fname) == "files.txt":
        handle_transfers()
        return

    # Handle installer file
    if fname[-3:] != "txt":
        arguments["-path"] = fname

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
        except (IOError, OSError) as e:
            print(e)
            sleep(0.5)

        return

    # Parse txt into dict as json
    try:
        print("Processing text file as args...")
        with open(fname, "r") as f:
            argstr = f.readlines()[0]
            arguments.update(loads(argstr))

        # Remove file from folder
        remove(fname)
    except IOError as e:
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
