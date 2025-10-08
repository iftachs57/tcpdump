import os

from actions.basic_actions import Report, SaveToPC, PckLists, ConvertToDict
from consts import consts


def Start():
    running = True
    file_path = ""
    while running:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(consts.Main_Menu)
        usrinp = input()
        if usrinp == "1":
            print(consts.Enter_File_Location)
            file_path = input()
            os.system('cls' if os.name == 'nt' else 'clear')
        elif usrinp == "2":
            if file_path != "":
                Report(file_path)
                print(consts.Press)
                input()
                os.system('cls' if os.name == 'nt' else 'clear')
            else:
                print(consts.Not_File_Path)
                print(consts.Press)
                input()
                os.system('cls' if os.name == 'nt' else 'clear')
        elif usrinp == "3":
            if file_path != "":
                print(consts.Saving_Location)
                saving_path = input()
                print(consts.Enter_Files_Name)
                files_name = input()
                pcklst, errlst = PckLists(file_path)
                data = ConvertToDict(pcklst, errlst)
                SaveToPC(saving_path, files_name, data)
                print(consts.Press)
                input()
                os.system('cls' if os.name == 'nt' else 'clear')
            else:
                print(consts.Not_File_Path)
                print(consts.Press)
                input()
        elif usrinp == "4":
            print(consts.Exit_Massage)
            running = False
        else:
            print(consts.Input_Error)
            input()
