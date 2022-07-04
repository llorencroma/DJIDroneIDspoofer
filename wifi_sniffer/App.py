import sys
import tkinter
import tkinter.messagebox
from tkintermapview import TkinterMapView


class App(tkinter.Tk):

    APP_NAME = "DJI sniffer"
    WIDTH = 1500
    HEIGHT = 700

    def __init__(self, *args, **kwargs):
        tkinter.Tk.__init__(self, *args, **kwargs)

        self.title(self.APP_NAME)
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")

        self.protocol("WM_DELETE_WINDOW", self.on_closing)


        if sys.platform == "darwin":
            self.bind("<Command-q>", self.on_closing)
            self.bind("<Command-w>", self.on_closing)

        # Set the map
        self.map_widget = TkinterMapView(width=self.WIDTH, height=self.HEIGHT, corner_radius=0)
        self.map_widget.grid(row=1, column=0, columnspan=3, sticky="nsew")

        # List of the markers (drones)
        self.marker_list = []

    # Add a new marker (drone)
    def save_marker(self,marker):
        self.marker_list.append(marker)

    # Clear the marker list
    def clear_marker_list(self):
        for m in self.marker_list:
            m.delete()
        self.marker_list.clear()

    def on_closing(self, event=0):
        self.destroy()
        exit()

    # To display the map
    def start(self):
        self.mainloop()
