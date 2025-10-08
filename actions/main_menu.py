from actions.basic_actions import Report, SaveToPC
from consts import consts


def Start():
    running = True
    file_path = ""
    saving_path = ""
    files_name = ""
    data = {}
    while running:
        print(consts.Main_Menu)
        usrinp = input()
        if usrinp == "1":
            print(consts.Enter_File_Location)
            file_path = input()
            continue
        if usrinp == "2":
            data = Report(file_path)
        if usrinp == "3":
            if data != None:
                print(consts.Saving_Location)
                saving_path = input()
                print(consts.Enter_Files_Name)
                files_name = input()
                SaveToPC(saving_path, files_name, data)
            else:

        if usrinp == "4":
            print(consts.Exit_Massage)
            running = False
        else:
            print(consts.Input_Error)
