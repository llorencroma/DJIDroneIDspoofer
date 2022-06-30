import sys
import tkinter
import tkinter.messagebox
from tkintermapview import TkinterMapView


class App(tkinter.Tk):

    APP_NAME = "DJI sniffer"
    WIDTH = 1000
    HEIGHT = 750

    def __init__(self, *args, **kwargs):
        tkinter.Tk.__init__(self, *args, **kwargs)

        self.title(self.APP_NAME)
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")

        self.protocol("WM_DELETE_WINDOW", self.on_closing)


        if sys.platform == "darwin":
            self.bind("<Command-q>", self.on_closing)
            self.bind("<Command-w>", self.on_closing)

        self.map_widget = TkinterMapView(width=self.WIDTH, height=600, corner_radius=0)
        self.map_widget.grid(row=1, column=0, columnspan=3, sticky="nsew")

        self.marker_list = []
        self.marker_path = None

    def save_marker(self,marker):
        self.marker_list.append(marker)

    def clear_marker_list(self):
        for m in self.marker_list:
            m.delete()
        self.marker_list.clear()

    def on_closing(self, event=0):
        self.destroy()
        exit()

    def start(self):
        self.mainloop()
