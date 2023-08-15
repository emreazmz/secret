import tkinter
from tkinter import END
from tkinter import messagebox
from PIL import ImageTk, Image
import base64

window = tkinter.Tk()
window.title("NoteBook")
window.geometry("750x800")

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
def save_entry():
    title12 = entry1.get()
    message = text1.get("1.0",tkinter.END)
    master_secret = entry2.get()
    if len(title12) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Hata!",message="Lütfen Tüm Bilgileri Girin")

    else:
        massage_encrypt = encode(master_secret,message)
        try:
            with open("mysecret.txt","a") as dataFile:
                dataFile.write(f"\n{title12}\n{massage_encrypt}")
        except FileNotFoundError:
            with open("mysecret.txt","w") as dataFile:
                dataFile.write(f"\n{title12}\n{massage_encrypt}")
        finally:
            entry1.delete(0,tkinter.END)
            entry2.delete(0, tkinter.END)
            text1.delete("1.0", tkinter.END)


def encryot_message():
    message_encrypt = text1.get("1.0", tkinter.END)
    master_secret = entry2.get()

    if len(message_encrypt) == 0 or len(master_secret) == 0:
     messagebox.showinfo(title="Hata!",message="Lütfen Tüm Bilgileri Girin!")
    else:
        try:
         decrtpr_message = decode(master_secret,message_encrypt)
         text1.delete("1.0",tkinter.END)
         text1.insert("1.0",decrtpr_message)
        except:
            messagebox.showinfo(title="Hata!",message="Lütfen Encrypt Edilmiş Mesajı Girmeyin")


label = tkinter.Label(text="NoteBook",font=('Arial',15))
label.pack()

frame = tkinter.Frame(window, width=200, height=300)
frame.pack()

img = Image.open("indir.png")
img = ImageTk.PhotoImage(img)

label1 = tkinter.Label(frame, image=img,padx=10,pady=5)
label1.pack()

label2 = tkinter.Label(text="Enter your title")
label2.pack()

entry1 = tkinter.Entry(width=30)
entry1.focus()
entry1.pack()

label3 = tkinter.Label(text="Enter your secret")
label3.pack()

text1 = tkinter.Text(width=18,height=15,padx=10,pady=10)
text1.pack()

label4 = tkinter.Label(text="Enter master key")
label4.pack()

entry2 = tkinter.Entry(width=25)
entry2.pack()

button1 = tkinter.Button(text= "Save & Encrypt",width=15,command=save_entry)
button1.pack()

button2 = tkinter.Button(text="Decrypt",width=10,command=encryot_message)
button2.pack()












tkinter.mainloop()