import tkinter as tk
from ctypes import cast, POINTER
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume

def change_volume(key):
    volume.SetMasterVolumeLevelScalar(int(key) / 10, None)

app = tk.Tk()
app.title("Volume Control")
app.geometry("300x200")

label = tk.Label(app, text="Press 1-0 keys to set volume")
label.pack(pady=20)

devices = AudioUtilities.GetSpeakers()
interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
volume = cast(interface, POINTER(IAudioEndpointVolume))

app.bind('1', lambda event: change_volume('1'))
app.bind('2', lambda event: change_volume('2'))
app.bind('3', lambda event: change_volume('3'))
app.bind('4', lambda event: change_volume('4'))
app.bind('5', lambda event: change_volume('5'))
app.bind('6', lambda event: change_volume('6'))
app.bind('7', lambda event: change_volume('7'))
app.bind('8', lambda event: change_volume('8'))
app.bind('9', lambda event: change_volume('9'))
app.bind('0', lambda event: change_volume('0'))

app.mainloop()
