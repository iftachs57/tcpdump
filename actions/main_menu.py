import os

from actions.basic_actions import report, save_to_pc, pck_lists, convert_pck_to_dict, ip_count, clear_console
from consts import consts

### Starts the interactive command-line interface for the packet analysis tool.
### Allows the user to input a PCAP file path, generate reports, save data to JSON, or exit.
def start():
    running = True
    file_path = ""
    while running:
        clear_console()
        print(consts.Main_Menu)
        usrinp = input()

        # Option 1: Input PCAP/PCAPNG file path
        if usrinp == "1":
            print(consts.Enter_File_Location)
            file_path = input()
            clear_console()

        # Option 2: Show report for current file
        elif usrinp == "2":
            if file_path != "":
                report(file_path)
                print(consts.Press)
                input()
                clear_console()
            else:
                print(consts.Not_File_Path)
                print(consts.Press)
                input()
                clear_console()

        # Option 3: Save packet data and IP stats to JSON
        elif usrinp == "3":
            if file_path != "":
                print(consts.Saving_Location)
                saving_path = input()
                print(consts.Enter_Files_Name)
                files_name = input()
                pcklst, errlst = pck_lists(file_path)
                data = convert_pck_to_dict(pcklst, errlst)
                count = ip_count(pcklst)
                save_to_pc(saving_path, files_name, data, count)
                print(consts.Press)
                input()
                clear_console()
            else:
                print(consts.Not_File_Path)
                print(consts.Press)
                input()

        # Option 4: Exit the program
        elif usrinp == "4":
            print(consts.Exit_Massage)
            running = False

        # Invalid input
        else:
            print(consts.Input_Error)
            input()
