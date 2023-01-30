from customtkinter import *
from tkinter import *
from tkmacosx import SFrame


class UI:
    def __init__(self):
        self.root = CTk()
        self.root.geometry("780x520")
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        self.frame_left = CTkFrame(master=self.root,
                                   width=180,
                                   corner_radius=0)
        self.frame_left.grid(row=0, column=0, sticky="nswe")
        self.frame_left.grid_rowconfigure(0, minsize=10)  # empty row with minsize as spacing
        self.frame_left.grid_rowconfigure(5, weight=1)  # empty row as spacing
        self.frame_left.grid_rowconfigure(8, minsize=20)  # empty row with minsize as spacing
        self.frame_left.grid_rowconfigure(11, minsize=10)  # empty row with minsize as spacing
        self.frame_right = CTkFrame(master=self.root)
        self.frame_right.grid(row=0, column=1, sticky="nswe", padx=20, pady=20)
        self.frame_right.rowconfigure(0, weight=1)
        self.frame_right.rowconfigure(7, weight=10)
        self.frame_right.columnconfigure(0, weight=1)
        self.frame_right.columnconfigure(2, weight=0)
        self.frame_info = CTkFrame(master=self.frame_right)
        self.frame_info.grid(row=0, column=0, columnspan=2, rowspan=4, pady=20, padx=20, sticky="nsew")
        self.frame_info.rowconfigure(0, weight=1)
        self.frame_info.columnconfigure(0, weight=1)
        self.label_info_1 = CTkLabel(master=self.frame_info,
                                     text="",
                                     height=250,
                                     corner_radius=6,
                                     fg_color=("white", "gray38"),
                                     justify=LEFT)
        self.label_info_1.grid(column=0, row=0, sticky="nwe", padx=15, pady=15)
        self.btn_frame = SFrame(self.frame_left, scrollbarwidth=3, bg=self.frame_left.fg_color[1], height=450)
        self.btn_frame.place(anchor="nw")
        self.label_1 = CTkLabel(master=self.frame_left,
                                text="HOSTS",
                                text_font=("Roboto Medium", -16, "underline"))  # font name and size in px
        self.label_1.grid(row=10, column=0, pady=10, padx=20, sticky="w")
        self.all_start_btn = CTkButton(master=self.frame_right, text="Spoof All")
        self.all_start_btn.place(x=25, y=380)
        self.all_stop_btn = CTkButton(master=self.frame_right, text="Stop All")
        self.all_stop_btn.place(x=395, y=380)
        self.exit_btn = CTkButton(master=self.frame_right, text="Exit", command=exit)
        self.exit_btn.place(x=210, y=425)
        self.root.mainloop()